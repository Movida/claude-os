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
use alloc::vec::Vec;
use faillible::{FileFaillible, VecFaillible};

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
    /// Si la mémoire manque, la charge est jetée, et Err le dit : l'émetteur la renverra, pourvu
    /// qu'on ne la lui ait pas annoncée.
    pub fn ranger(&mut self, mut seq: u32, mut charge: P) -> Result<Option<(u32, u32)>, ()> {
        let debut = seq;
        let fin_charge = seq.wrapping_add(charge.octets().len() as u32);
        let mut doublon = None;
        if charge.octets().is_empty() {
            return Ok(None);
        }
        if self.file.try_reserve(1).is_err() {
            return Err(());
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
                return Ok(Some((debut, fin_charge)));
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
        self.file.inserer_dans_la_place(i, (seq, charge));
        Ok(doublon)
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

    /// Le numéro de la charge la plus lointaine, et celui qui la suit (`ooo_last_skb`).
    pub fn derniere_seq(&self) -> Option<u32> {
        self.file.back().map(|e| e.0)
    }

    pub fn derniere_fin(&self) -> Option<u32> {
        self.file.back().map(fin)
    }

    /// Jette la charge la plus lointaine, pour faire de la place à ce qui
    /// arrive dans l'ordre (`tcp_prune_ofo_queue`) ; rend sa taille vraie (0 :
    /// il n'y avait rien).
    pub fn jeter_la_derniere(&mut self) -> usize {
        match self.file.pop_back() {
            Some((_, p)) => {
                let v = p.taille_vraie();
                self.taille_vraie = self.taille_vraie.saturating_sub(v);
                v
            }
            None => 0,
        }
    }

    /// `tcp_collapse_ofo_queue` : chaque suite sans trou recopiée en paquets denses
    /// de `taille` octets, à partir de son premier paquet de mauvais rendement (d'après
    /// `ratio`). Une suite d'un seul petit paquet n'y gagnerait rien, et s'il y en a
    /// beaucoup (plus de `limite` en taille vraie), la mémoire n'est pas là : on s'arrête.
    pub fn fondre(&mut self, taille: usize, limite: usize, ratio: u8) {
        let mut petits = 0;
        let mut i = 0;
        while i < self.file.len() {
            let debut = self.file[i].0;
            let mut bout = fin(&self.file[i]);
            let mut vraie = self.file[i].1.taille_vraie();
            let mut j = i + 1;
            while let Some(e) = self.file.get(j) {
                if apres(e.0, bout) {
                    break;
                }
                vraie += e.1.taille_vraie();
                bout = fin(e);
                j += 1;
            }
            if j > i + 1 || bout.wrapping_sub(debut) as usize >= taille {
                let avant_ = self.file.len();
                self.recopier(i, j, taille, ratio);
                // Toute la suite occupe maintenant moins, ou autant, de places.
                i = (j + self.file.len()).saturating_sub(avant_);
            } else {
                petits += vraie;
                if petits > limite {
                    return;
                }
                i = j;
            }
        }
    }

    /// Recopie les entrées `i..j`, à partir de la première de mauvais rendement.
    fn recopier(&mut self, i: usize, j: usize, taille: usize, ratio: u8) {
        let gaspille = |p: &P| ((p.taille_vraie() as i64 * ratio as i64) >> 8) > p.octets().len() as i64;
        let Some(premier) = (i..j).find(|&k| gaspille(&self.file[k].1)) else { return };
        let total: usize = (premier..j).map(|k| self.file[k].1.octets().len()).sum();
        let mut seq = self.file[premier].0;
        let mut neuves: Vec<(u32, P)> = Vec::new();
        if neuves.try_reserve(total.div_ceil(taille)).is_err() || self.file.try_reserve(total.div_ceil(taille)).is_err() {
            return;
        }
        let (mut k, mut decalage, mut reste) = (premier, 0, total);
        while reste > 0 {
            let n = reste.min(taille);
            let Some(mut neuve) = P::neuve(n) else { return };
            let mut fait = 0;
            while fait < n {
                let o = &self.file[k].1.octets()[decalage..];
                let m = o.len().min(n - fait);
                neuve.completer(&o[..m]);
                fait += m;
                decalage += m;
                if decalage == self.file[k].1.octets().len() {
                    k += 1;
                    decalage = 0;
                }
            }
            neuves.ajouter_dans_la_place((seq, neuve));
            seq = seq.wrapping_add(n as u32);
            reste -= n;
        }
        for (_, p) in self.file.drain(premier..j) {
            self.taille_vraie = self.taille_vraie.saturating_sub(p.taille_vraie());
        }
        for (n, e) in neuves.into_iter().enumerate() {
            self.taille_vraie += e.1.taille_vraie();
            self.file.inserer_dans_la_place(premier + n, e);
        }
    }

    /// Jette tout (la connexion se ferme).
    pub fn vider(&mut self) {
        self.file.clear();
        self.taille_vraie = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::super::essais::{octets, Octets};
    use super::*;
    use alloc::vec;

    fn charge(n: usize) -> Octets {
        Octets(vec![1; n], 0, 2 * n)
    }

    #[test]
    fn etendre_le_doublon() {
        let mut d = None;
        etendre_doublon(&mut d, 10, 20);
        assert_eq!(d, Some((10, 20)));
        etendre_doublon(&mut d, 20, 30);
        assert_eq!(d, Some((10, 30)));
    }

    /// `tcp_data_queue_ofo` : ce qui est déjà là, et ce qui le chevauche.
    #[test]
    fn ranger_() {
        let mut h: HorsOrdre<Octets> = HorsOrdre::new();
        assert_eq!(h.ranger(100, charge(10)), Ok(None));
        assert_eq!(h.taille_vraie, 20);
        // Entièrement couvert : le doublon, rien de plus.
        assert_eq!(h.ranger(102, charge(4)), Ok(Some((102, 106))));
        assert_eq!(h.ranger(100, charge(10)), Ok(Some((100, 110))));
        assert_eq!(h.file.len(), 1);
        // Son début est déjà là : retiré, et dit.
        assert_eq!(h.ranger(105, charge(10)), Ok(Some((105, 110))));
        assert_eq!(h.file.len(), 2);
        assert_eq!(h.file[1].0, 110);
        assert_eq!(h.file[1].1.octets().len(), 5);
        // Il couvre tout un autre : celui-là disparaît, et sa taille avec lui.
        let mut h: HorsOrdre<Octets> = HorsOrdre::new();
        h.ranger(100, charge(5)).unwrap();
        assert_eq!(h.ranger(90, charge(30)), Ok(Some((100, 105))));
        assert_eq!(h.file.len(), 1);
        assert_eq!(h.taille_vraie, 60);
        // Vide : rien.
        assert_eq!(h.ranger(500, charge(0)), Ok(None));
        assert_eq!(h.file.len(), 1);
    }

    /// `tcp_collapse_ofo_queue` : une suite sans trou se recopie, si elle a des gaspilleurs.
    #[test]
    fn fondre_une_suite() {
        let mut h: HorsOrdre<Octets> = HorsOrdre::new();
        // Deux suites : 100..300 (mauvais rendement), 500..600 (seule, petite).
        h.ranger(100, octets(100, 1000)).unwrap();
        h.ranger(200, octets(100, 1000)).unwrap();
        h.ranger(500, octets(100, 1000)).unwrap();
        h.fondre(150, 1 << 20, 128);
        // 100..300, recopié par 150 ; le reste, tel quel.
        assert_eq!(h.file.len(), 3);
        assert_eq!((h.file[0].0, h.file[0].1.octets().len()), (100, 150));
        assert_eq!((h.file[1].0, h.file[1].1.octets().len()), (250, 50));
        assert_eq!((h.file[2].0, h.file[2].1.taille_vraie()), (500, 1000));
        let vraie: usize = h.file.iter().map(|e| e.1.taille_vraie()).sum();
        assert_eq!(h.taille_vraie, vraie);
        // Une seule entrée, assez grande pour la taille : recopiée aussi.
        let mut h: HorsOrdre<Octets> = HorsOrdre::new();
        h.ranger(100, octets(100, 1000)).unwrap();
        h.fondre(100, 1 << 20, 128);
        assert_ne!(h.file[0].1.taille_vraie(), 1000);
        // Une de plus petite que la taille : non.
        let mut h: HorsOrdre<Octets> = HorsOrdre::new();
        h.ranger(100, octets(100, 1000)).unwrap();
        h.fondre(101, 1 << 20, 128);
        assert_eq!(h.file[0].1.taille_vraie(), 1000);
    }

    /// `tcp_collapse_ofo_queue` : les petites suites gardées ne vont pas au-delà de la limite : la
    /// suite ne vaut plus la peine.
    #[test]
    fn fondre_s_arrete_a_la_limite() {
        let prete = || {
            let mut h: HorsOrdre<Octets> = HorsOrdre::new();
            h.ranger(100, octets(10, 1000)).unwrap();
            h.ranger(200, octets(10, 1000)).unwrap();
            h.ranger(300, octets(10, 1000)).unwrap();
            h.ranger(310, octets(10, 1000)).unwrap();
            h
        };
        // Au-delà de la limite : la dernière suite n'est pas vue.
        let mut h = prete();
        h.fondre(3000, 1999, 128);
        assert_eq!(h.file.len(), 4);
        // Tout juste à la limite : on continue.
        let mut h = prete();
        h.fondre(3000, 2000, 128);
        assert_eq!(h.file.len(), 3);
    }

    /// Seulement à partir du premier de mauvais rendement, et rien s'il n'y en a pas.
    #[test]
    fn recopier_le_mauvais_rendement() {
        // Rendement : (vraie × ratio) >> 8 > longueur.
        let mut h: HorsOrdre<Octets> = HorsOrdre::new();
        h.ranger(100, octets(100, 200)).unwrap();
        h.ranger(200, octets(100, 200)).unwrap();
        h.fondre(1000, 1 << 20, 128);
        assert_eq!(h.file.len(), 2, "tout juste bon : (200 × 128) >> 8 = 100");
        let mut h: HorsOrdre<Octets> = HorsOrdre::new();
        h.ranger(100, octets(100, 200)).unwrap();
        h.ranger(200, octets(100, 202)).unwrap();
        h.fondre(1000, 1 << 20, 128);
        assert_eq!(h.file.len(), 2, "le premier reste, le second recopié");
        assert_eq!(h.file[0].1.taille_vraie(), 200);
        assert_ne!(h.file[1].1.taille_vraie(), 202);
    }

    /// La connexion se ferme : tout s'en va.
    #[test]
    fn vider_() {
        let mut h: HorsOrdre<Octets> = HorsOrdre::new();
        h.ranger(1000, octets(100, 200)).unwrap();
        h.vider();
        assert!(h.vide());
        assert_eq!(h.taille_vraie, 0);
    }
}
