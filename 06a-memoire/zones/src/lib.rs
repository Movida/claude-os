//! La carte des zones d'un programme : les plages d'adresses qu'il a le
//! droit de toucher, chacune avec ses droits (les `vm_area_struct` de
//! Linux, mm/mmap.c).
//!
//! Jusqu'à l'étape 5, c'étaient les tables de pages qui disaient ce qu'un
//! programme pouvait toucher : tout était projeté d'avance, et une page
//! absente était une erreur. Ce n'est plus tenable : `claude` réserve 8 Gio
//! pour n'en toucher que quelques Mio. Comme Linux, on sépare donc deux
//! choses :
//!   - la CARTE DES ZONES dit ce qui est permis : « de 0x7f00_0000_0000 à
//!     0x7f02_0000_0000, lecture et écriture, mémoire anonyme » ;
//!   - les TABLES DE PAGES disent ce qui est en place : elles se
//!     remplissent à la faute de page, dans les zones seulement.
//! Une faute de page dans une zone n'est plus une erreur : le noyau donne
//! la page et le programme reprend (la pagination à la demande).
//!
//! Une zone : un début et une fin alignés sur la page (début < fin), des
//! droits (lecture, écriture, exécution), une nature (pour les messages)
//! et des drapeaux. Les invariants, vérifiés après chaque opération par les
//! tests :
//!   - les zones sont triées, disjointes, non vides ;
//!   - deux voisines contiguës et du même genre (mêmes droits, même nature,
//!     mêmes drapeaux) sont toujours fusionnées en une seule : c'est le
//!     `vma_merge` de Linux. Sans lui, le moteur JavaScript de `claude`,
//!     qui change sans cesse les droits de morceaux de sa mémoire
//!     (`mprotect`), émietterait la carte en milliers de zones ;
//!   - il y en a au plus `ZONES_MAX`.
//!
//! Toute opération qui peut ajouter des zones réserve d'abord la place
//! (`try_reserve`) et vérifie le maximum : en cas d'échec, RIEN n'a changé.
//! Le noyau n'a ainsi jamais à défaire une opération à moitié faite.
//!
//! La structure : un tableau trié (`Vec`), où l'on cherche par dichotomie.
//! Options écartées :
//!   - l'arbre d'érable (maple tree) de Linux depuis 6.1, ou l'arbre
//!     rouge-noir d'avant : des recherches en O(log n) ET des insertions en
//!     O(log n). Le tableau a des insertions en O(n) (on décale la suite),
//!     mais `claude` a 78 zones à l'accueil (mesuré) : la dichotomie fait 7
//!     comparaisons, une insertion déplace 2 Kio. Linux a d'ailleurs vécu
//!     vingt ans avec une liste chaînée doublée d'un arbre. On changera si
//!     une mesure le demande ;
//!   - `BTreeMap` de `alloc` : il panique quand la mémoire manque (pas de
//!     `try_insert`), et une allocation ratée ne doit jamais arrêter le
//!     noyau. Un `Vec` sait échouer proprement (`try_reserve`).
//!
//! La recherche d'un trou (`trou`) parcourt les zones une à une : O(n).
//! Linux tient dans chaque nœud de son arbre la taille du plus grand trou
//! dessous, pour la faire en O(log n) ; à 78 zones, ce n'est pas la peine.
//!
//! La bibliothèque ne sait rien des tables de pages : elle dit au noyau ce
//! qu'il doit faire (par exemple, chaque morceau retiré, pour qu'il en
//! rende les pages). Sans `unsafe`, testée sur l'hôte (cas écrits à la
//! main, puis des milliers d'opérations au hasard comparées à un modèle
//! page par page, tests/modele.rs).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// La taille d'une page : toutes les bornes de zones y sont alignées.
pub const PAGE: u64 = 4096;

/// Le plus de zones qu'un programme peut avoir : le `vm.max_map_count` de
/// Linux par défaut (65 530). Au-delà, l'opération échoue (ENOMEM pour le
/// programme). La borne protège le noyau d'un programme qui émietterait
/// sa mémoire en millions de zones, chacune une entrée du tableau.
pub const ZONES_MAX: usize = 65_530;

/// Ce qu'un programme peut faire dans une zone (PROT_READ, PROT_WRITE,
/// PROT_EXEC). Sans aucun droit (PROT_NONE), la zone est réservée mais
/// inaccessible : une page de garde, ou une réservation qu'on rendra
/// accessible plus tard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Droits {
    pub lecture: bool,
    pub ecriture: bool,
    pub execution: bool,
}

impl Droits {
    pub const AUCUN: Droits = Droits { lecture: false, ecriture: false, execution: false };

    /// La zone peut-elle être touchée d'une façon ou d'une autre ? Sur x86,
    /// écrire ou exécuter permet aussi de lire : le processeur ne sait pas
    /// interdire la lecture d'une page présente (le `vma_is_accessible` de
    /// Linux).
    pub fn accessible(&self) -> bool {
        self.lecture || self.ecriture || self.execution
    }
}

/// D'où vient une zone : pour les messages (« dans bonjour-c[401000+...] »)
/// et pour ce que le noyau y fait (un `MADV_DONTNEED` sur un segment du
/// programme, par exemple). Deux zones de natures différentes ne fusionnent
/// jamais.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nature {
    /// Un segment de l'exécutable.
    Programme,
    /// Le tas (brk).
    Tas,
    /// La pile du programme.
    Pile,
    /// De la mémoire anonyme (mmap).
    Anonyme,
}

/// Les drapeaux d'une zone, ceux de Linux qui ont un sens pour nous.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Drapeaux {
    /// La zone grandit vers le bas : une faute juste sous elle l'étend (la
    /// pile, VM_GROWSDOWN). Personne ne doit s'installer à moins de l'écart
    /// de garde sous elle (voir `libre`).
    pub vers_le_bas: bool,
    /// Pas de réservation : la zone ne compte pas dans la politique de
    /// surengagement (MAP_NORESERVE, VM_NORESERVE).
    pub sans_reserve: bool,
    /// Pas copiée dans l'enfant d'un fork (MADV_DONTFORK, VM_DONTCOPY).
    pub ne_pas_dupliquer: bool,
    /// Copiée à zéro dans l'enfant d'un fork (MADV_WIPEONFORK,
    /// VM_WIPEONFORK).
    pub effacer_au_fork: bool,
}

/// Une zone : les adresses [debut, fin[, alignées sur la page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Zone {
    pub debut: u64,
    pub fin: u64,
    pub droits: Droits,
    pub nature: Nature,
    pub drapeaux: Drapeaux,
}

impl Zone {
    pub fn taille(&self) -> u64 {
        self.fin - self.debut
    }

    pub fn contient(&self, adresse: u64) -> bool {
        (self.debut..self.fin).contains(&adresse)
    }

    /// Les deux zones ont-elles les mêmes droits, la même nature et les
    /// mêmes drapeaux ? Contiguës, elles n'en font alors qu'une.
    pub fn meme_genre(&self, autre: &Zone) -> bool {
        self.droits == autre.droits && self.nature == autre.nature && self.drapeaux == autre.drapeaux
    }

    /// Le début de la zone, écart de garde compris : une zone qui grandit
    /// vers le bas réserve `ecart` octets sous elle, pour pouvoir grandir
    /// (le `vm_start_gap` de Linux). Jamais sous 0.
    fn debut_garde(&self, ecart: u64) -> u64 {
        if self.drapeaux.vers_le_bas { self.debut.saturating_sub(ecart) } else { self.debut }
    }
}

/// Pourquoi une opération est refusée. Rien n'a alors changé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Bornes non alignées sur la page, ou plage vide ou à l'envers.
    PlageInvalide,
    /// La zone à insérer chevauche une zone existante.
    Chevauchement,
    /// L'opération dépasserait le nombre maximal de zones.
    TropDeZones,
    /// Plus de mémoire pour agrandir le tableau.
    PlusDeMemoire,
}

/// Où chercher un trou : en partant du haut (la disposition de Linux sur
/// x86_64, « top-down », sous la pile) ou du bas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sens {
    DuHaut,
    DuBas,
}

/// La carte des zones d'un programme.
pub struct Zones {
    /// Triées, disjointes, non vides, voisines de même genre fusionnées.
    zones: Vec<Zone>,
    /// Le plus de zones permis (ZONES_MAX, sauf dans les tests).
    maximum: usize,
}

fn alignee(adresse: u64) -> bool {
    adresse % PAGE == 0
}

impl Default for Zones {
    fn default() -> Self {
        Zones::new()
    }
}

impl Zones {
    /// Une carte vide, sans rien allouer.
    pub const fn new() -> Zones {
        Zones { zones: Vec::new(), maximum: ZONES_MAX }
    }

    /// Une carte vide, avec de la place pour `capacite` zones d'avance.
    pub fn avec_capacite(capacite: usize) -> Result<Zones, Erreur> {
        let mut zones = Zones::new();
        zones.zones.try_reserve_exact(capacite).map_err(|_| Erreur::PlusDeMemoire)?;
        Ok(zones)
    }

    /// Une carte vide qui n'accepte que `maximum` zones : pour tester le
    /// cas du maximum atteint sans en créer 65 530.
    pub fn avec_maximum(maximum: usize) -> Zones {
        Zones { zones: Vec::new(), maximum }
    }

    /// Les zones, dans l'ordre des adresses.
    pub fn zones(&self) -> &[Zone] {
        &self.zones
    }

    pub fn nombre(&self) -> usize {
        self.zones.len()
    }

    /// L'indice de la première zone qui finit après `adresse` : celle qui
    /// la contient, ou sinon la première au-dessus (dichotomie).
    fn indice_apres(&self, adresse: u64) -> usize {
        self.zones.partition_point(|z| z.fin <= adresse)
    }

    /// La zone qui contient `adresse`.
    pub fn trouver(&self, adresse: u64) -> Option<&Zone> {
        self.zones.get(self.indice_apres(adresse)).filter(|z| z.debut <= adresse)
    }

    /// La première zone qui finit après `adresse` : celle qui la contient,
    /// ou la première au-dessus (le `find_vma` de Linux).
    pub fn suivante(&self, adresse: u64) -> Option<&Zone> {
        self.zones.get(self.indice_apres(adresse))
    }

    /// La dernière zone qui finit à `adresse` ou avant.
    pub fn precedente(&self, adresse: u64) -> Option<&Zone> {
        self.indice_apres(adresse).checked_sub(1).map(|i| &self.zones[i])
    }

    /// Les morceaux des zones compris dans [debut, fin[ : chaque zone qui
    /// y touche, coupée à ces bornes.
    pub fn morceaux(&self, debut: u64, fin: u64) -> impl Iterator<Item = Zone> + '_ {
        self.zones[self.indice_apres(debut)..]
            .iter()
            .take_while(move |z| z.debut < fin)
            .map(move |z| Zone { debut: z.debut.max(debut), fin: z.fin.min(fin), ..*z })
    }

    /// Les zones couvrent-elles [debut, fin[ sans trou ? (Une plage vide
    /// est couverte.)
    pub fn couverte(&self, debut: u64, fin: u64) -> bool {
        let mut prochain = debut;
        for z in self.morceaux(debut, fin) {
            if z.debut != prochain {
                return false;
            }
            prochain = z.fin;
        }
        prochain >= fin
    }

    /// La plage [debut, fin[ est-elle libre, en laissant l'écart de garde
    /// `ecart` sous une zone qui grandit vers le bas ? C'est la question
    /// que pose Linux pour une adresse suggérée à mmap, ou pour le tas qui
    /// grandit.
    pub fn libre(&self, debut: u64, fin: u64, ecart: u64) -> bool {
        match self.suivante(debut) {
            None => true,
            Some(z) => fin <= z.debut_garde(ecart),
        }
    }

    /// Un trou d'au moins `taille` octets (multiple de la page, non nul)
    /// dans [plancher, plafond[, en laissant l'écart de garde sous les
    /// zones qui grandissent vers le bas. Du haut : l'adresse la plus haute
    /// possible ; du bas : la plus basse. C'est le `vm_unmapped_area` de
    /// Linux, sans contrainte d'alignement.
    pub fn trou(&self, taille: u64, plancher: u64, plafond: u64, ecart: u64, sens: Sens) -> Option<u64> {
        if taille == 0 || !alignee(taille) || plafond < plancher || plafond - plancher < taille {
            return None;
        }
        // Le trou sous la zone i va de la fin de la zone i - 1 (ou de 0)
        // jusqu'au début, écart compris, de la zone i (ou jusqu'en haut,
        // pour i = nombre de zones). On le coupe à [plancher, plafond[.
        let bornes = |i: usize| {
            let bas = if i == 0 { 0 } else { self.zones[i - 1].fin };
            let haut = self.zones.get(i).map_or(u64::MAX, |z| z.debut_garde(ecart));
            (bas.max(plancher), haut.min(plafond))
        };
        let assez = |(bas, haut): (u64, u64)| haut > bas && haut - bas >= taille;
        match sens {
            Sens::DuHaut => {
                // Le premier trou à regarder est sous la première zone qui
                // finit après le plafond.
                let premier = self.indice_apres(plafond);
                (0..=premier).rev().map(bornes).find(|&b| assez(b)).map(|(_, haut)| haut - taille)
            }
            Sens::DuBas => {
                let premier = self.indice_apres(plancher);
                (premier..=self.zones.len()).map(bornes).find(|&b| assez(b)).map(|(bas, _)| bas)
            }
        }
    }

    /// Ajoute une zone, là où il n'y a rien. Elle fusionne avec ses
    /// voisines contiguës du même genre.
    pub fn inserer(&mut self, zone: Zone) -> Result<(), Erreur> {
        if !alignee(zone.debut) || !alignee(zone.fin) || zone.debut >= zone.fin {
            return Err(Erreur::PlageInvalide);
        }
        let i = self.indice_apres(zone.debut);
        if self.zones.get(i).is_some_and(|z| z.debut < zone.fin) {
            return Err(Erreur::Chevauchement);
        }
        let avec_avant = i > 0 && self.zones[i - 1].fin == zone.debut && self.zones[i - 1].meme_genre(&zone);
        let avec_apres = self.zones.get(i).is_some_and(|z| z.debut == zone.fin && z.meme_genre(&zone));
        match (avec_avant, avec_apres) {
            // Elle comble le trou entre deux zones de son genre : les trois
            // n'en font plus qu'une, il y a une zone de moins.
            (true, true) => {
                self.zones[i - 1].fin = self.zones[i].fin;
                self.zones.remove(i);
            }
            (true, false) => self.zones[i - 1].fin = zone.fin,
            (false, true) => self.zones[i].debut = zone.debut,
            (false, false) => {
                self.place_pour(1)?;
                self.zones.insert(i, zone);
            }
        }
        Ok(())
    }

    /// Vérifie qu'on peut ajouter `n` zones, et réserve leur place.
    fn place_pour(&mut self, n: usize) -> Result<(), Erreur> {
        if self.zones.len() + n > self.maximum {
            return Err(Erreur::TropDeZones);
        }
        self.zones.try_reserve(n).map_err(|_| Erreur::PlusDeMemoire)
    }

    /// Retire de la carte tout ce qui est dans [debut, fin[, en coupant les
    /// zones à ces bornes, et appelle `retire` pour chaque morceau retiré
    /// (dans l'ordre des adresses) : le noyau en rend les pages. Une plage
    /// où il n'y a rien n'est pas une erreur (munmap rend alors 0).
    ///
    /// Couper une zone en son milieu en fait deux : c'est la seule façon
    /// dont un retrait ajoute une zone, et il peut alors échouer (Linux
    /// rend ENOMEM à munmap dans ce cas).
    pub fn retirer(&mut self, debut: u64, fin: u64, mut retire: impl FnMut(&Zone)) -> Result<(), Erreur> {
        if !alignee(debut) || !alignee(fin) || debut > fin {
            return Err(Erreur::PlageInvalide);
        }
        // Une plage vide, même au milieu d'une zone, ne retire rien (et ne
        // doit surtout pas la couper autour de rien).
        if debut == fin {
            return Ok(());
        }
        let i = self.indice_apres(debut);
        let Some(&premiere) = self.zones.get(i).filter(|z| z.debut < fin) else {
            return Ok(());
        };
        if premiere.debut < debut && premiere.fin > fin {
            // Un trou au milieu d'une zone : elle devient deux.
            self.place_pour(1)?;
            retire(&Zone { debut, fin, ..premiere });
            self.zones[i].fin = debut;
            self.zones.insert(i + 1, Zone { debut: fin, ..premiere });
            return Ok(());
        }
        // Sinon, de i à j (exclu) les zones qui touchent la plage : la
        // première peut garder son début, la dernière sa fin, les autres
        // disparaissent en entier.
        let j = i + self.zones[i..].iter().take_while(|z| z.debut < fin).count();
        for z in &self.zones[i..j] {
            retire(&Zone { debut: z.debut.max(debut), fin: z.fin.min(fin), ..*z });
        }
        let mut garde_debut = 0;
        if self.zones[i].debut < debut {
            self.zones[i].fin = debut;
            garde_debut = 1;
        }
        let mut garde_fin = 0;
        if self.zones[j - 1].fin > fin && j - 1 >= i + garde_debut {
            self.zones[j - 1].debut = fin;
            garde_fin = 1;
        }
        self.zones.drain(i + garde_debut..j - garde_fin);
        Ok(())
    }

    /// Change les zones dans [debut, fin[ (là où il y en a) par `change`,
    /// qui modifie les droits, la nature ou les drapeaux d'une zone (ses
    /// bornes, s'il les touche, sont remises). Les zones sont coupées aux
    /// bornes de la plage, puis les voisines devenues du même genre
    /// fusionnées. C'est mprotect et madvise.
    ///
    /// Une zone que `change` laisse telle quelle n'est pas coupée (comme
    /// Linux, qui ne touche pas une zone dont les droits ne changent pas).
    /// Couper ajoute au plus deux zones, et les fusions en retirent : si le
    /// compte final dépasse le maximum, rien ne change.
    pub fn changer(&mut self, debut: u64, fin: u64, change: impl Fn(&mut Zone)) -> Result<(), Erreur> {
        if !alignee(debut) || !alignee(fin) || debut > fin {
            return Err(Erreur::PlageInvalide);
        }
        if debut == fin {
            return Ok(());
        }
        let changee = |z: &Zone| {
            let mut copie = *z;
            change(&mut copie);
            Zone { debut: z.debut, fin: z.fin, ..copie }
        };
        let i = self.indice_apres(debut);
        let j = i + self.zones[i..].iter().take_while(|z| z.debut < fin).count();
        if i == j {
            return Ok(());
        }
        // Les coupes nécessaires : au début, si la première zone commence
        // avant la plage ; à la fin, si la dernière finit après. Chacune
        // seulement si la zone change vraiment.
        let coupe_debut = self.zones[i].debut < debut && changee(&self.zones[i]) != self.zones[i];
        let coupe_fin = self.zones[j - 1].fin > fin && changee(&self.zones[j - 1]) != self.zones[j - 1];
        let coupes = coupe_debut as usize + coupe_fin as usize;
        // Le nombre de zones après l'opération, sans rien toucher : on
        // passe en revue les morceaux qu'elle laissera, de la voisine
        // d'avant à celle d'après, et on compte les fusions. (Un `mprotect`
        // qui coupe une zone mais rend le morceau du même genre que sa
        // voisine ne doit pas être refusé quand la carte est pleine : le
        // compte, au bout du compte, ne change pas.)
        let mut fusions = 0;
        let mut derniere: Option<Zone> = i.checked_sub(1).map(|k| self.zones[k]);
        let mut voir = |z: Zone| {
            if derniere.is_some_and(|d| d.fin == z.debut && d.meme_genre(&z)) {
                fusions += 1;
            }
            derniere = Some(z);
        };
        if coupe_debut {
            voir(Zone { fin: debut, ..self.zones[i] });
        }
        for k in i..j {
            let z = self.zones[k];
            let bas = if k == i && coupe_debut { debut } else { z.debut };
            let haut = if k == j - 1 && coupe_fin { fin } else { z.fin };
            let morceau = Zone { debut: bas, fin: haut, ..z };
            voir(if bas >= debut && haut <= fin { changee(&morceau) } else { morceau });
        }
        if coupe_fin {
            voir(Zone { debut: fin, ..self.zones[j - 1] });
        }
        if let Some(&apres) = self.zones.get(j) {
            voir(apres);
        }
        if self.zones.len() + coupes - fusions > self.maximum {
            return Err(Erreur::TropDeZones);
        }
        // La place des coupes, avant les fusions qui la rendront.
        self.zones.try_reserve(coupes).map_err(|_| Erreur::PlusDeMemoire)?;
        // Les coupes, de la fin vers le début : les indices de la plage ne
        // bougent qu'après.
        let (mut i, mut j) = (i, j);
        if coupe_fin {
            let z = self.zones[j - 1];
            self.zones[j - 1].fin = fin;
            self.zones.insert(j, Zone { debut: fin, ..z });
        }
        if coupe_debut {
            let z = self.zones[i];
            self.zones[i].fin = debut;
            self.zones.insert(i + 1, Zone { debut, ..z });
            i += 1;
            j += 1;
        }
        for k in i..j {
            // Une zone qui dépasse encore la plage ne change pas (sinon on
            // l'aurait coupée).
            if self.zones[k].debut >= debut && self.zones[k].fin <= fin {
                self.zones[k] = changee(&self.zones[k]);
            }
        }
        // Les fusions : dans la plage, et avec la voisine de chaque côté.
        self.fusionner(i.saturating_sub(1), (j + 1).min(self.zones.len()));
        Ok(())
    }

    /// Fusionne les voisines contiguës du même genre parmi les zones
    /// d'indices [de, a[.
    fn fusionner(&mut self, de: usize, a: usize) {
        let mut k = de + 1;
        let mut a = a;
        while k < a {
            let (avant, z) = (self.zones[k - 1], self.zones[k]);
            if avant.fin == z.debut && avant.meme_genre(&z) {
                self.zones[k - 1].fin = z.fin;
                self.zones.remove(k);
                a -= 1;
            } else {
                k += 1;
            }
        }
    }

    /// Étend vers le bas, jusqu'à `adresse` (alignée), la zone qui grandit
    /// vers le bas juste au-dessus : une faute de page sous la pile (le
    /// `expand_downwards` de Linux). Refusé (false, rien ne change) si la
    /// zone au-dessus de l'adresse ne grandit pas vers le bas, si elle
    /// dépasserait `taille_max` octets (RLIMIT_STACK), ou si une zone
    /// accessible finit à moins de `ecart` octets sous l'adresse (l'écart
    /// de garde : la pile ne doit pas venir se coller à une autre zone, où
    /// un débordement écrirait en silence). Une zone sans aucun droit (une
    /// page de garde posée par le programme lui-même) ne compte pas pour
    /// l'écart, comme dans Linux.
    pub fn etendre_pile(&mut self, adresse: u64, taille_max: u64, ecart: u64) -> bool {
        if !alignee(adresse) {
            return false;
        }
        let i = self.indice_apres(adresse);
        let Some(pile) = self.zones.get(i) else { return false };
        if pile.debut <= adresse || !pile.drapeaux.vers_le_bas || pile.fin - adresse > taille_max {
            return false;
        }
        if let Some(avant) = i.checked_sub(1).map(|k| &self.zones[k])
            && avant.droits.accessible()
            && !avant.drapeaux.vers_le_bas
            && adresse - avant.fin < ecart
        {
            return false;
        }
        self.zones[i].debut = adresse;
        // Collée à la zone d'en dessous (sans droits, ou un écart nul) :
        // elles ne fusionnent que si elles sont du même genre.
        self.fusionner(i.saturating_sub(1), i + 1);
        true
    }

    /// Les invariants de la carte (voir l'en-tête) sont-ils respectés ? Pour
    /// les tests.
    pub fn invariants(&self) -> Result<(), &'static str> {
        if self.zones.len() > self.maximum {
            return Err("trop de zones");
        }
        for z in &self.zones {
            if !alignee(z.debut) || !alignee(z.fin) {
                return Err("zone non alignee");
            }
            if z.debut >= z.fin {
                return Err("zone vide ou a l'envers");
            }
        }
        for paire in self.zones.windows(2) {
            if paire[0].fin > paire[1].debut {
                return Err("zones non triees ou qui se chevauchent");
            }
            if paire[0].fin == paire[1].debut && paire[0].meme_genre(&paire[1]) {
                return Err("voisines du meme genre non fusionnees");
            }
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    const RW: Droits = Droits { lecture: true, ecriture: true, execution: false };
    const R: Droits = Droits { lecture: true, ecriture: false, execution: false };
    const RX: Droits = Droits { lecture: true, ecriture: false, execution: true };

    fn anonyme(debut: u64, fin: u64, droits: Droits) -> Zone {
        Zone { debut: debut * PAGE, fin: fin * PAGE, droits, nature: Nature::Anonyme, drapeaux: Drapeaux::default() }
    }

    fn pile(debut: u64, fin: u64) -> Zone {
        Zone { nature: Nature::Pile, drapeaux: Drapeaux { vers_le_bas: true, ..Drapeaux::default() }, ..anonyme(debut, fin, RW) }
    }

    /// La carte sous forme de (début, fin) en pages, pour comparer.
    fn pages(z: &Zones) -> Vec<(u64, u64)> {
        z.zones().iter().map(|z| (z.debut / PAGE, z.fin / PAGE)).collect()
    }

    fn carte(zones: &[Zone]) -> Zones {
        let mut c = Zones::new();
        for &z in zones {
            c.inserer(z).unwrap();
        }
        c.invariants().unwrap();
        c
    }

    #[test]
    fn insertion_et_fusion() {
        let mut c = carte(&[anonyme(10, 20, RW), anonyme(30, 40, RW)]);
        assert_eq!(c.inserer(anonyme(15, 25, RW)), Err(Erreur::Chevauchement));
        assert_eq!(c.inserer(anonyme(5, 11, RW)), Err(Erreur::Chevauchement));
        assert_eq!(c.inserer(anonyme(39, 41, RW)), Err(Erreur::Chevauchement));
        assert_eq!(c.inserer(Zone { fin: 20 * PAGE + 1, ..anonyme(20, 21, RW) }), Err(Erreur::PlageInvalide));
        assert_eq!(c.inserer(anonyme(20, 20, RW)), Err(Erreur::PlageInvalide));
        // Contiguë des deux côtés, du même genre : une seule zone.
        c.inserer(anonyme(20, 30, RW)).unwrap();
        assert_eq!(pages(&c), [(10, 40)]);
        // Contiguë mais d'un autre genre : pas de fusion.
        c.inserer(anonyme(40, 50, R)).unwrap();
        c.inserer(Zone { nature: Nature::Tas, ..anonyme(50, 60, R) }).unwrap();
        assert_eq!(pages(&c), [(10, 40), (40, 50), (50, 60)]);
        c.invariants().unwrap();
        assert_eq!(c.trouver(10 * PAGE).map(|z| z.fin), Some(40 * PAGE));
        assert_eq!(c.trouver(40 * PAGE - 1).map(|z| z.debut), Some(10 * PAGE));
        assert_eq!(c.trouver(9 * PAGE + 4095), None);
        assert_eq!(c.trouver(60 * PAGE), None);
        assert_eq!(c.suivante(0).map(|z| z.debut), Some(10 * PAGE));
        assert_eq!(c.precedente(40 * PAGE).map(|z| z.debut), Some(10 * PAGE));
        assert!(c.precedente(10 * PAGE).is_none());
    }

    #[test]
    fn retrait() {
        let mut c = carte(&[anonyme(10, 20, RW), anonyme(30, 40, R), anonyme(50, 60, RX)]);
        let mut retires = Vec::new();
        // Au milieu d'une zone : elle devient deux.
        c.retirer(12 * PAGE, 14 * PAGE, |z| retires.push((z.debut / PAGE, z.fin / PAGE))).unwrap();
        assert_eq!(pages(&c), [(10, 12), (14, 20), (30, 40), (50, 60)]);
        // À cheval sur trois zones : un bout de chaque côté, une en entier.
        c.retirer(15 * PAGE, 55 * PAGE, |z| retires.push((z.debut / PAGE, z.fin / PAGE))).unwrap();
        assert_eq!(pages(&c), [(10, 12), (14, 15), (55, 60)]);
        assert_eq!(retires, [(12, 14), (15, 20), (30, 40), (50, 55)]);
        // Rien dans la plage : pas d'erreur, rien de retiré. Une plage vide
        // au milieu d'une zone ne la coupe pas.
        c.retirer(20 * PAGE, 50 * PAGE, |_| panic!("rien a retirer")).unwrap();
        c.retirer(11 * PAGE, 11 * PAGE, |_| panic!("rien a retirer")).unwrap();
        c.retirer(PAGE, PAGE, |_| panic!("rien a retirer")).unwrap();
        // Exactement une zone ; puis tout.
        c.retirer(14 * PAGE, 15 * PAGE, |_| ()).unwrap();
        assert_eq!(pages(&c), [(10, 12), (55, 60)]);
        c.retirer(0, 100 * PAGE, |_| ()).unwrap();
        assert!(c.zones().is_empty());
        assert_eq!(c.retirer(1, PAGE, |_| ()), Err(Erreur::PlageInvalide));
    }

    #[test]
    fn changement_de_droits() {
        let mut c = carte(&[anonyme(10, 40, RW)]);
        // Le milieu en lecture seule : trois zones.
        c.changer(20 * PAGE, 30 * PAGE, |z| z.droits = R).unwrap();
        assert_eq!(pages(&c), [(10, 20), (20, 30), (30, 40)]);
        // Rendu à ses droits : une seule zone de nouveau.
        c.changer(20 * PAGE, 30 * PAGE, |z| z.droits = RW).unwrap();
        assert_eq!(pages(&c), [(10, 40)]);
        // Sans changement, ou sur une plage vide : pas de coupe.
        c.changer(15 * PAGE, 25 * PAGE, |z| z.droits = RW).unwrap();
        c.changer(15 * PAGE, 15 * PAGE, |z| z.droits = R).unwrap();
        assert_eq!(pages(&c), [(10, 40)]);
        // Une plage plus large que la zone, avec des trous : seules les
        // parties projetées changent.
        c.inserer(anonyme(50, 60, RX)).unwrap();
        c.changer(0, 100 * PAGE, |z| z.droits = R).unwrap();
        assert_eq!(pages(&c), [(10, 40), (50, 60)]);
        assert!(c.zones().iter().all(|z| z.droits == R));
        // Devenues du même genre et contiguës : elles fusionnent.
        c.inserer(anonyme(40, 50, RW)).unwrap();
        c.changer(40 * PAGE, 50 * PAGE, |z| z.droits = R).unwrap();
        assert_eq!(pages(&c), [(10, 60)]);
        // Les bornes, si `change` les touche, sont remises.
        c.changer(10 * PAGE, 20 * PAGE, |z| {
            z.debut = 0;
            z.droits = RW;
        }).unwrap();
        assert_eq!(pages(&c), [(10, 20), (20, 60)]);
        c.invariants().unwrap();
    }

    #[test]
    fn maximum_de_zones() {
        let mut c = Zones::avec_maximum(2);
        c.inserer(anonyme(10, 20, RW)).unwrap();
        c.inserer(anonyme(30, 40, RW)).unwrap();
        assert_eq!(c.inserer(anonyme(50, 60, RW)), Err(Erreur::TropDeZones));
        // Une insertion qui fusionne n'ajoute pas de zone : permise.
        c.inserer(anonyme(40, 45, RW)).unwrap();
        c.inserer(anonyme(20, 30, RW)).unwrap();
        assert_eq!(pages(&c), [(10, 45)]);
        c.inserer(anonyme(50, 60, RW)).unwrap();
        // Couper en deux ferait une troisième zone : refusé, rien ne change.
        assert_eq!(c.retirer(12 * PAGE, 13 * PAGE, |_| panic!("rien ne doit etre retire")), Err(Erreur::TropDeZones));
        assert_eq!(c.changer(12 * PAGE, 13 * PAGE, |z| z.droits = R), Err(Erreur::TropDeZones));
        assert_eq!(pages(&c), [(10, 45), (50, 60)]);
        // Un changement d'une zone entière ne coupe rien.
        c.changer(50 * PAGE, 60 * PAGE, |z| z.droits = R).unwrap();
        // Une coupe dont le morceau rejoint sa voisine : le compte ne
        // change pas, c'est permis.
        let mut c = Zones::avec_maximum(2);
        c.inserer(anonyme(10, 20, RW)).unwrap();
        c.inserer(anonyme(20, 30, R)).unwrap();
        c.changer(15 * PAGE, 20 * PAGE, |z| z.droits = R).unwrap();
        assert_eq!(pages(&c), [(10, 15), (15, 30)]);
    }

    #[test]
    fn couverture_et_morceaux() {
        let c = carte(&[anonyme(10, 20, RW), anonyme(20, 30, R), anonyme(40, 50, RW)]);
        assert!(c.couverte(10 * PAGE, 30 * PAGE));
        assert!(c.couverte(15 * PAGE, 25 * PAGE));
        assert!(!c.couverte(15 * PAGE, 35 * PAGE));
        assert!(!c.couverte(5 * PAGE, 15 * PAGE));
        assert!(c.couverte(35 * PAGE, 35 * PAGE));
        let m: Vec<_> = c.morceaux(15 * PAGE, 45 * PAGE).map(|z| (z.debut / PAGE, z.fin / PAGE)).collect();
        assert_eq!(m, [(15, 20), (20, 30), (40, 45)]);
    }

    #[test]
    fn trous() {
        let ecart = 4 * PAGE;
        let c = carte(&[anonyme(10, 20, RW), anonyme(30, 40, RW), pile(90, 100)]);
        // Du haut, sous un plafond de 100 pages : la pile réserve 4 pages
        // sous elle, le trou le plus haut finit donc à 86.
        assert_eq!(c.trou(5 * PAGE, 0, 100 * PAGE, ecart, Sens::DuHaut), Some(81 * PAGE));
        // Un trou de 10 pages tient tout juste entre 20 et 30.
        assert_eq!(c.trou(10 * PAGE, 0, 30 * PAGE, ecart, Sens::DuHaut), Some(20 * PAGE));
        // 11 pages : nulle part sous 30 ; 10 pages sous 20 : seulement
        // tout en bas, et plus du tout au-dessus d'un plancher.
        assert_eq!(c.trou(11 * PAGE, 0, 30 * PAGE, ecart, Sens::DuHaut), None);
        assert_eq!(c.trou(10 * PAGE, 0, 20 * PAGE, ecart, Sens::DuHaut), Some(0));
        assert_eq!(c.trou(10 * PAGE, PAGE, 20 * PAGE, ecart, Sens::DuHaut), None);
        // Du bas, au-dessus d'un plancher.
        assert_eq!(c.trou(5 * PAGE, 12 * PAGE, 100 * PAGE, ecart, Sens::DuBas), Some(20 * PAGE));
        assert_eq!(c.trou(20 * PAGE, 12 * PAGE, 100 * PAGE, ecart, Sens::DuBas), Some(40 * PAGE));
        // Au-dessus de la pile : pas d'écart à garder.
        assert_eq!(c.trou(PAGE, 95 * PAGE, 200 * PAGE, ecart, Sens::DuBas), Some(100 * PAGE));
        assert_eq!(c.trou(0, 0, 200 * PAGE, ecart, Sens::DuBas), None);
        assert!(c.libre(80 * PAGE, 86 * PAGE, ecart));
        assert!(!c.libre(80 * PAGE, 87 * PAGE, ecart));
        assert!(!c.libre(15 * PAGE, 16 * PAGE, ecart));
        assert!(c.libre(100 * PAGE, u64::MAX / PAGE * PAGE, ecart));
    }

    #[test]
    fn pile_qui_grandit() {
        let ecart = 4 * PAGE;
        let mut c = carte(&[anonyme(10, 20, RW), pile(90, 100)]);
        // Jusqu'à 20 pages de pile.
        assert!(c.etendre_pile(85 * PAGE, 20 * PAGE, ecart));
        assert!(c.etendre_pile(80 * PAGE, 20 * PAGE, ecart));
        assert!(!c.etendre_pile(79 * PAGE, 20 * PAGE, ecart));
        assert_eq!(pages(&c), [(10, 20), (80, 100)]);
        // L'écart de garde au-dessus d'une zone accessible.
        assert!(c.etendre_pile(24 * PAGE, 80 * PAGE, ecart));
        assert!(!c.etendre_pile(23 * PAGE, 80 * PAGE, ecart));
        // Une zone sans droits ne compte pas pour l'écart.
        let mut c = carte(&[anonyme(10, 20, Droits::AUCUN), pile(90, 100)]);
        assert!(c.etendre_pile(20 * PAGE, 80 * PAGE, ecart));
        assert_eq!(pages(&c), [(10, 20), (20, 100)]);
        // Pas sous une zone qui ne grandit pas, ni dans une zone.
        let mut c = carte(&[anonyme(30, 40, RW), pile(90, 100)]);
        assert!(!c.etendre_pile(25 * PAGE, 80 * PAGE, ecart));
        assert!(!c.etendre_pile(95 * PAGE, 80 * PAGE, ecart));
        assert!(!c.etendre_pile(100 * PAGE, 80 * PAGE, ecart));
        assert!(!c.etendre_pile(85 * PAGE + 1, 80 * PAGE, ecart));
        c.invariants().unwrap();
    }
}
