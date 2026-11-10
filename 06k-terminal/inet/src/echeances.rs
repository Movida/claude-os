//! Les échéances précises du réseau : celles qui ne peuvent pas attendre le tic de la roue
//! (../roue) : ce que Linux confie à ses hrtimers (la compression des SACK), ou à une tâche sans
//! délai (la fin d'émission de TSQ). Chaque objet a AU PLUS UNE échéance ; il n'y en a jamais
//! que quelques-unes à la fois.
//!
//! Choix de conception. Une liste triée, de capacité fixée à sa création (au démarrage), une
//! entrée par objet : armer déplace l'entrée de l'objet, désarmer la retire. Exacte, simple, et
//! réservée d'avance. Option écartée : un tas binaire dont on laisse les entrées périmées en
//! place (rien n'en borne le nombre, et il garde sa capacité).
//!
//! L'heure est un argument (en nanosecondes) : testé sur l'hôte contre un
//! modèle naïf.

use alloc::vec::Vec;
use faillible::VecFaillible;

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
        // La place de `max` entrées est prise à la création (`new`).
        self.entrees.inserer_dans_la_place(i, (echeance, objet));
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
