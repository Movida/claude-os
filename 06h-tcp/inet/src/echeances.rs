//! Les échéances du réseau (6h) : quand la tâche du réseau doit se
//! réveiller, et pour qui. Chaque objet (la table des voisins, puis chaque
//! connexion TCP, chaque entrée de TIME_WAIT) a AU PLUS UNE échéance, la
//! plus proche des siennes ; la tâche dort jusqu'à la première, puis prend
//! celles qui sont échues et fait le travail de leur objet.
//!
//! Choix de conception. Une liste triée, de capacité fixée à sa création
//! (au démarrage), une entrée par objet : armer déplace l'entrée de
//! l'objet (plus tôt ou plus tard), désarmer la retire. Linux prend une
//! « roue » de minuteurs (kernel/time/timer.c) : ses minuteurs se comptent
//! par centaines de milliers et sont presque tous annulés avant de tomber
//! (celui de retransmission de TCP est réarmé à chaque ACK), d'où des
//! opérations en temps constant, au prix d'une précision qui baisse avec
//! l'éloignement. Nous en avons quelques dizaines à la fois (la table des
//! voisins, les connexions de claude et de nos tests, leurs TIME_WAIT) :
//! une liste triée est exacte, simple, et, réservée d'avance, ne prend
//! jamais de mémoire pendant un programme (le lanceur mesure la mémoire
//! rendue). Armer coûte un parcours et un déplacement des entrées
//! PRÉSENTES (pas de la capacité, réservée pour 8192 objets depuis TCP),
//! sous un verrou court, à chaque changement d'échéance : quelques
//! centaines d'octets aujourd'hui ; un serveur aux milliers de connexions
//! demandera la roue de Linux. Option écartée aussi : un tas binaire dont
//! on laisse les entrées périmées en place (rien n'en borne le nombre, et
//! il garde sa capacité).
//!
//! L'heure est un argument (en nanosecondes) : testé sur l'hôte contre un
//! modèle naïf.

use alloc::vec::Vec;

/// Plus de place : la liste est pleine (elle a sa taille définitive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pleine;

/// Les échéances, triées de la plus proche à la plus lointaine (à égalité,
/// dans l'ordre où elles ont été armées).
pub struct Echeances {
    entrees: Vec<(u64, u64)>,
    max: usize,
}

impl Echeances {
    /// Une liste pour `max` objets à la fois. None : plus de mémoire.
    pub fn new(max: usize) -> Option<Echeances> {
        let mut entrees = Vec::new();
        entrees.try_reserve_exact(max).ok()?;
        Some(Echeances { entrees, max })
    }

    /// L'objet `objet` doit être servi à `echeance` (ns) : son ancienne
    /// échéance, s'il en avait une, est remplacée. Pleine : rien ne change
    /// (l'ancienne échéance reste).
    pub fn armer(&mut self, objet: u64, echeance: u64) -> Result<(), Pleine> {
        let ancienne = self.entrees.iter().position(|&(_, o)| o == objet);
        if ancienne.is_none() && self.entrees.len() >= self.max {
            return Err(Pleine);
        }
        if let Some(i) = ancienne {
            self.entrees.remove(i);
        }
        let i = self.entrees.partition_point(|&(e, _)| e <= echeance);
        self.entrees.insert(i, (echeance, objet));
        Ok(())
    }

    /// L'objet `objet` n'a plus d'échéance.
    pub fn desarmer(&mut self, objet: u64) {
        if let Some(i) = self.entrees.iter().position(|&(_, o)| o == objet) {
            self.entrees.remove(i);
        }
    }

    /// L'échéance de l'objet `objet`, s'il en a une.
    pub fn echeance(&self, objet: u64) -> Option<u64> {
        self.entrees.iter().find(|&&(_, o)| o == objet).map(|&(e, _)| e)
    }

    /// La plus proche des échéances.
    pub fn prochaine(&self) -> Option<u64> {
        self.entrees.first().map(|&(e, _)| e)
    }

    /// Le premier objet dont l'échéance est passée à `maintenant`, retiré
    /// de la liste (son objet le réarmera s'il le faut).
    pub fn prendre_echu(&mut self, maintenant: u64) -> Option<u64> {
        match self.entrees.first() {
            Some(&(e, o)) if e <= maintenant => {
                self.entrees.remove(0);
                Some(o)
            }
            _ => None,
        }
    }

    /// Le nombre d'objets qui ont une échéance.
    pub fn len(&self) -> usize {
        self.entrees.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entrees.is_empty()
    }
}
