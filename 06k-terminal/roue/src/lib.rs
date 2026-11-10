//! La roue des minuteurs : `kernel/time/timer.c` de Linux, avec sa structure et ses constantes.
//!
//! LE PROBLÈME. Un noyau arme énormément de minuteurs, et presque aucun ne part : celui de la
//! retransmission de TCP est repoussé à chaque ACK. Il faut donc que les armer et les désarmer ne
//! coûte rien ; qu'ils partent à la milliseconde près n'a aucun intérêt : un délai qui expire, c'est
//! que les choses vont déjà mal.
//!
//! LA ROUE. Neuf niveaux de 64 cases. Une case du niveau 0 vaut un tic ; d'un niveau au suivant, 8
//! fois plus. Un minuteur va dans le niveau que demande son éloignement, sans jamais en descendre
//! (Linux 4.8 a retiré la « cascade », le travail qu'il fallait pour le redescendre). Avec HZ à
//! 250 :
//!     niveau 0 :   4 ms par case, jusqu'à 255 ms
//!     niveau 1 :  32 ms, jusqu'à 2 s
//!     niveau 2 : 256 ms, jusqu'à 16 s
//!     niveau 3 :   2 s, jusqu'à 2 min
//!     ...
//!     niveau 8 :  18 h, jusqu'à 49 jours
//! Une échéance est arrondie au-dessus, à la case qui suit : elle ne part jamais trop tôt, et au
//! plus un huitième environ trop tard (une case du niveau n vaut 8/63 du plus petit délai qui y va).
//! Chaque niveau a ses 64 cases en bits : la prochaine échéance se lit sans rien parcourir.
//!
//! LE TIC : 4 ms (HZ 250, le réglage par défaut du noyau de Linux, et celui de la machine qui sert
//! de référence à nos sondes), bien que notre horloge batte à la milliseconde : un programme y
//! voit les mêmes arrondis que sous Linux. Écarté : HZ à 1000 : plus précis, ce que la roue
//! n'a justement pas à être ; ce qui doit l'être (les hrtimers de Linux) va ailleurs.
//!
//! LES ENTRÉES. Chez Linux, le minuteur est dans l'objet (`struct timer_list`), et la roue n'en
//! tient que la chaîne. Ici, les objets ne sont que des numéros (une socket, une entrée de
//! TIME_WAIT) : la roue a sa réserve d'entrées, chaînées par indices (la `hlist`, en indices), et une
//! table numéro → entrée. Écarté : garder l'entrée dans l'objet, que tiennent des verrous variés :
//! l'objet devrait alors rester en vie tant que son minuteur court, et chaque appelant tenir sa
//! poignée. La réserve, elle, est prise une fois pour toutes : armer n'alloue jamais.
//!
//! UNE SEULE BASE, pour l'instant ; une par processeur avec le multiprocesseur (6j).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use faillible::VecFaillible;

/// Plus de place : la réserve est pleine (elle a sa taille définitive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pleine;

/// La durée d'un tic, en ns : HZ 250.
pub const TIC: u64 = 4_000_000;

const CLK_SHIFT: u32 = 3;
const CLK_DIV: u64 = 1 << CLK_SHIFT;
const CLK_MASK: u64 = CLK_DIV - 1;
const BITS: u32 = 6;
const TAILLE: u64 = 1 << BITS;
const MASK: u64 = TAILLE - 1;
const NIVEAUX: usize = 9;
const CASES: usize = NIVEAUX * TAILLE as usize;

const fn decalage(n: u32) -> u32 {
    n * CLK_SHIFT
}

const fn granularite(n: u32) -> u64 {
    1 << decalage(n)
}

/// Le début du niveau `n` : le dernier délai du niveau d'avant, pour qu'on puisse encore ajouter
/// une granularité à l'échéance (`LVL_START`).
const fn debut(n: u32) -> u64 {
    (TAILLE - 1) << ((n - 1) * CLK_SHIFT)
}

/// `WHEEL_TIMEOUT_CUTOFF`, `WHEEL_TIMEOUT_MAX`.
const COUPURE: u64 = debut(NIVEAUX as u32);
const DELAI_MAX: u64 = COUPURE - granularite(NIVEAUX as u32 - 1);
/// Sans minuteur, la prochaine échéance est repoussée d'autant (`TIMER_NEXT_MAX_DELTA`).
const AUCUNE_AVANT: u64 = (1 << 30) - 1;

const RIEN: u32 = u32::MAX;
/// La chaîne de ceux dont l'heure est passée, pas encore rendus : une case de plus.
const ECHUS: usize = CASES;

#[derive(Clone, Copy)]
struct Entree {
    objet: u64,
    /// Son échéance, en tics, et en ns (ce qu'on a demandé).
    expire: u64,
    echeance: u64,
    suivant: u32,
    precedent: u32,
    case: u16,
}

/// La roue (`struct timer_base`).
pub struct Roue {
    /// La tête de chaque case, et des échus.
    tetes: Vec<u32>,
    /// Les cases occupées (`pending_map`) : 64 bits par niveau.
    occupees: [u64; NIVEAUX],
    /// Le tic suivant à traiter (`clk`), et la plus proche case occupée (`next_expiry`) ; à
    /// recalculer si elle a pu se vider (`next_expiry_recalc`) ; des minuteurs, ou non
    /// (`timers_pending`).
    clk: u64,
    prochain: u64,
    recalculer: bool,
    en_attente: bool,
    entrees: Vec<Entree>,
    libre: u32,
    /// numéro → entrée : adressage ouvert, 2 fois la capacité au moins.
    places: Vec<u32>,
    decalage_places: u32,
    nombre: usize,
}

impl Roue {
    /// Une roue pour `max` objets à la fois. None : plus de mémoire.
    pub fn new(max: usize) -> Option<Roue> {
        let tetes = faillible::remplie(CASES + 1, RIEN).ok()?;
        let mut entrees = Vec::new();
        entrees.try_reserve_exact(max).ok()?;
        for k in 0..max {
            let suivant = if k + 1 < max { k as u32 + 1 } else { RIEN };
            entrees.ajouter_dans_la_place(Entree { objet: 0, expire: 0, echeance: 0, suivant, precedent: RIEN, case: 0 });
        }
        let taille = (2 * max).max(2).next_power_of_two();
        let places = faillible::remplie(taille, RIEN).ok()?;
        Some(Roue {
            tetes,
            occupees: [0; NIVEAUX],
            clk: 0,
            prochain: AUCUNE_AVANT,
            recalculer: false,
            en_attente: false,
            entrees,
            libre: if max > 0 { 0 } else { RIEN },
            places,
            decalage_places: 64 - taille.trailing_zeros(),
            nombre: 0,
        })
    }

    // --- La table numéro → entrée ---

    fn hachage(&self, objet: u64) -> usize {
        // Le hachage de Fibonacci : les numéros se suivent, et il les étale.
        (objet.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> self.decalage_places) as usize
    }

    /// La place de l'objet dans la table, ou celle où il irait.
    fn place(&self, objet: u64) -> usize {
        let masque = self.places.len() - 1;
        let mut p = self.hachage(objet);
        loop {
            let i = self.places[p];
            if i == RIEN || self.entrees[i as usize].objet == objet {
                return p;
            }
            p = (p + 1) & masque;
        }
    }

    fn entree(&self, objet: u64) -> Option<usize> {
        let i = self.places[self.place(objet)];
        (i != RIEN).then_some(i as usize)
    }

    /// Retire l'objet de la table, en recollant ceux qui le suivaient (adressage ouvert : pas de
    /// trou dans une suite, ou on ne les trouverait plus).
    fn oublier(&mut self, objet: u64) {
        let masque = self.places.len() - 1;
        let mut trou = self.place(objet);
        let mut p = trou;
        loop {
            p = (p + 1) & masque;
            let i = self.places[p];
            if i == RIEN {
                break;
            }
            let chez_lui = self.hachage(self.entrees[i as usize].objet);
            // Il peut aller dans le trou si son point de départ n'est pas entre le trou et lui.
            if (p.wrapping_sub(chez_lui) & masque) >= (p.wrapping_sub(trou) & masque) {
                self.places[trou] = i;
                trou = p;
            }
        }
        self.places[trou] = RIEN;
    }

    // --- La roue ---

    /// La case d'une échéance, et l'heure de cette case (`calc_index`) : arrondie au-dessus, à la
    /// granularité du niveau : pour ne jamais partir trop tôt, même armée au bord d'un tic.
    fn case_de_niveau(expire: u64, niveau: u32) -> (usize, u64) {
        let e = (expire >> decalage(niveau)) + 1;
        ((niveau as u64 * TAILLE + (e & MASK)) as usize, e << decalage(niveau))
    }

    /// `calc_wheel_index`.
    fn case(&self, mut expire: u64) -> (usize, u64) {
        let delta = expire.wrapping_sub(self.clk);
        if (delta as i64) < 0 {
            // Déjà passée : la case du tic courant.
            return ((self.clk & MASK) as usize, self.clk);
        }
        for n in 1..NIVEAUX as u32 {
            if delta < debut(n) {
                return Self::case_de_niveau(expire, n - 1);
            }
        }
        // Au-delà de ce que la roue tient : à sa limite.
        if delta >= COUPURE {
            expire = self.clk + DELAI_MAX;
        }
        Self::case_de_niveau(expire, NIVEAUX as u32 - 1)
    }

    /// Fait avancer `clk` jusqu'à maintenant, tant que rien n'est dû : un minuteur armé après un
    /// long silence est rangé par rapport à l'heure qu'il est (`__forward_timer_base`).
    fn avancer(&mut self, tics: u64) {
        if tics <= self.clk {
            return;
        }
        if self.recalculer {
            self.recalculer();
        }
        if !self.en_attente {
            // Rien en attente : l'échéance de repli suit, ou un minuteur très lointain la dépasserait.
            self.clk = tics;
            self.prochain = tics + AUCUNE_AVANT;
        } else if self.prochain > tics {
            self.clk = tics;
        } else if self.prochain >= self.clk {
            self.clk = self.prochain;
        }
    }

    fn accrocher(&mut self, i: usize, case: usize) {
        let tete = self.tetes[case];
        self.entrees[i].suivant = tete;
        self.entrees[i].precedent = RIEN;
        self.entrees[i].case = case as u16;
        if tete != RIEN {
            self.entrees[tete as usize].precedent = i as u32;
        }
        self.tetes[case] = i as u32;
    }

    /// `detach_if_pending`.
    fn decrocher(&mut self, i: usize) {
        let Entree { suivant, precedent, case, .. } = self.entrees[i];
        let case = case as usize;
        if precedent != RIEN {
            self.entrees[precedent as usize].suivant = suivant;
        } else {
            self.tetes[case] = suivant;
        }
        if suivant != RIEN {
            self.entrees[suivant as usize].precedent = precedent;
        }
        if case < CASES && self.tetes[case] == RIEN {
            self.occupees[case / TAILLE as usize] &= !(1 << (case as u64 & MASK));
            self.recalculer = true;
        }
    }

    /// `enqueue_timer`.
    fn ranger(&mut self, i: usize, case: usize, heure: u64) {
        self.accrocher(i, case);
        self.occupees[case / TAILLE as usize] |= 1 << (case as u64 & MASK);
        if heure < self.prochain {
            self.prochain = heure;
            self.recalculer = false;
        }
        // Même si elle tombe pile sur l'échéance de repli (49 jours plus tard) : elle partira.
        self.en_attente = true;
    }

    /// L'objet `objet` doit être servi à `echeance` (ns), qu'il soit déjà armé ou non (`__mod_timer`).
    /// Pleine : rien ne change. Temps constant, sans allocation.
    pub fn armer(&mut self, objet: u64, echeance: u64, maintenant: u64) -> Result<(), Pleine> {
        let expire = echeance / TIC;
        if let Some(i) = self.entree(objet) {
            let echu = self.entrees[i].case as usize == ECHUS;
            if !echu && self.entrees[i].expire == expire {
                self.entrees[i].echeance = echeance;
                return Ok(());
            }
            self.avancer(maintenant / TIC);
            let (case, heure) = self.case(expire);
            // La même case : ni la chaîne ni les bits ne changent : c'est le cas des minuteurs
            // repoussés souvent, de peu.
            if !echu && case == self.entrees[i].case as usize {
                self.entrees[i].expire = expire;
                self.entrees[i].echeance = echeance;
                return Ok(());
            }
            self.decrocher(i);
            self.entrees[i].expire = expire;
            self.entrees[i].echeance = echeance;
            self.ranger(i, case, heure);
            return Ok(());
        }
        if self.libre == RIEN {
            return Err(Pleine);
        }
        let i = self.libre as usize;
        self.libre = self.entrees[i].suivant;
        let p = self.place(objet);
        self.places[p] = i as u32;
        self.nombre += 1;
        self.entrees[i].objet = objet;
        self.entrees[i].expire = expire;
        self.entrees[i].echeance = echeance;
        self.avancer(maintenant / TIC);
        let (case, heure) = self.case(expire);
        self.ranger(i, case, heure);
        Ok(())
    }

    /// L'objet n'a plus d'échéance (`timer_delete`).
    pub fn desarmer(&mut self, objet: u64) {
        if let Some(i) = self.entree(objet) {
            self.decrocher(i);
            self.liberer(i);
        }
    }

    fn liberer(&mut self, i: usize) {
        self.oublier(self.entrees[i].objet);
        self.entrees[i].suivant = self.libre;
        self.libre = i as u32;
        self.nombre -= 1;
    }

    /// L'échéance de l'objet, s'il en a une.
    pub fn echeance(&self, objet: u64) -> Option<u64> {
        self.entree(objet).map(|i| self.entrees[i].echeance)
    }

    /// Le plus proche des bits de ce niveau à partir de `clk`, à sa distance (`next_pending_bucket`).
    fn case_suivante(bits: u64, clk: u64) -> Option<u64> {
        if bits == 0 {
            return None;
        }
        // La rotation met `clk` en bit 0 : la distance est le rang du premier bit posé.
        Some(bits.rotate_right((clk & MASK) as u32).trailing_zeros() as u64)
    }

    /// `timer_recalc_next_expiry`. La première échéance de chaque niveau, en s'arrêtant dès
    /// qu'elle arrive avant ce que le niveau suivant peut encore apporter.
    fn recalculer(&mut self) {
        let vide = self.clk + AUCUNE_AVANT;
        let mut prochain = vide;
        let mut clk = self.clk;
        for n in 0..NIVEAUX {
            let niveau_clk = clk & CLK_MASK;
            if let Some(pos) = Self::case_suivante(self.occupees[n], clk) {
                prochain = prochain.min((clk + pos) << decalage(n as u32));
                if pos <= (CLK_DIV - niveau_clk) & CLK_MASK {
                    break;
                }
            }
            clk >>= CLK_SHIFT;
            clk += u64::from(niveau_clk != 0);
        }
        self.prochain = prochain;
        self.recalculer = false;
        self.en_attente = self.occupees.iter().any(|&b| b != 0);
    }

    /// La plus proche échéance, en ns : à cette heure, `prendre_echu` a quelque chose à rendre.
    pub fn prochaine(&mut self) -> Option<u64> {
        if self.tetes[ECHUS] != RIEN {
            return Some(0);
        }
        if self.recalculer {
            self.recalculer();
        }
        self.en_attente.then_some(self.prochain.saturating_mul(TIC))
    }

    /// Passe les cases de `prochain` aux échus (`__collect_expired_timers`) : celle du niveau 0, et,
    /// quand ses bits bas sont nuls, celle du niveau d'au-dessus, etc.
    fn collecter(&mut self) {
        self.clk = self.prochain;
        let mut clk = self.clk;
        for n in 0..NIVEAUX {
            let bit = 1u64 << (clk & MASK);
            if self.occupees[n] & bit != 0 {
                self.occupees[n] &= !bit;
                let case = n * TAILLE as usize + (clk & MASK) as usize;
                let mut i = self.tetes[case];
                self.tetes[case] = RIEN;
                while i != RIEN {
                    let suivant = self.entrees[i as usize].suivant;
                    self.accrocher(i as usize, ECHUS);
                    i = suivant;
                }
            }
            if clk & CLK_MASK != 0 {
                break;
            }
            clk >>= CLK_SHIFT;
        }
    }

    /// Un objet dont l'heure est passée à `maintenant`, retiré (son objet le réarmera s'il le faut) ;
    /// None : aucun (`__run_timers`).
    pub fn prendre_echu(&mut self, maintenant: u64) -> Option<u64> {
        let tics = maintenant / TIC;
        loop {
            let i = self.tetes[ECHUS];
            if i != RIEN {
                let objet = self.entrees[i as usize].objet;
                self.decrocher(i as usize);
                self.liberer(i as usize);
                return Some(objet);
            }
            if self.recalculer {
                self.recalculer();
            }
            if !self.en_attente || tics < self.clk || tics < self.prochain {
                return None;
            }
            self.collecter();
            self.clk += 1;
            self.recalculer();
        }
    }

    /// Le nombre d'objets qui ont une échéance.
    pub fn len(&self) -> usize {
        self.nombre
    }

    pub fn is_empty(&self) -> bool {
        self.nombre == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Des numéros qui se suivent ne doivent pas se suivre dans la table : sinon, une longue suite à
    /// parcourir, et armer ne serait plus en temps constant.
    #[test]
    fn le_hachage_etale_les_numeros() {
        let r = Roue::new(512).unwrap();
        let mut vus = alloc::vec![false; r.places.len()];
        for n in 1..=512 {
            vus[r.hachage(n)] = true;
        }
        assert_eq!(vus.iter().filter(|&&v| v).count(), 512);
    }
}
