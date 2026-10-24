//! La mémoire d'un programme : sa carte des zones (ce qu'il a le droit de
//! toucher, ../zones), ses tables de pages (ce qui est en place,
//! espace_utilisateur.rs) et son tas. C'est la mm_struct de Linux.
//!
//! La carte fait foi : une page n'est projetée que dans une zone, avec les
//! droits de sa zone. Toute opération (brk, mprotect) change d'abord la
//! carte, qui peut refuser (trop de zones, plus de mémoire) sans rien avoir
//! changé ; puis seulement les tables, ce qui ne peut plus échouer.

use crate::espace_utilisateur::{CadreNeuf, Erreur, EspaceUtilisateur};
use zones::{Droits, Zone, Zones};

const PAGE: u64 = 4096;

impl From<zones::Erreur> for Erreur {
    fn from(e: zones::Erreur) -> Erreur {
        match e {
            zones::Erreur::PlageInvalide => Erreur::AdresseInterdite,
            zones::Erreur::Chevauchement => Erreur::DejaProjetee,
            // Pour le programme, les deux sont ENOMEM, comme dans Linux.
            zones::Erreur::TropDeZones | zones::Erreur::PlusDeMemoire => Erreur::PlusDeMemoire,
        }
    }
}

pub struct Memoire {
    pub espace: EspaceUtilisateur,
    pub zones: Zones,
    /// Le début du tas : la page qui suit le dernier segment (le .bss).
    pub debut_tas: u64,
    /// La fin du tas, à l'octet près (le « program break » de brk). La
    /// zone du tas va de son début à la page qui contient sa fin.
    pub fin_tas: u64,
}

impl Memoire {
    /// Une mémoire vide : pas de zones, un espace neuf. Le tas est placé
    /// par le chargeur.
    pub fn creer() -> Result<Memoire, Erreur> {
        // La carte occupe d'emblée une page entière (170 zones), et
        // grandit en blocs de pages : le tas du noyau prend les blocs de
        // plus de 2 Kio directement à l'allocateur de pages, et les lui
        // rend à la destruction du programme. Une petite carte, elle,
        // viendrait des classes du tas, qui gardent leurs pages même
        // vides (tas.rs) : la mémoire du premier programme qui atteint une
        // taille de carte ne reviendrait jamais à l'allocateur de pages, et
        // la vérification « memoire rendue » ne pourrait plus rien dire.
        let zones = Zones::avec_capacite(PAGE as usize / size_of::<Zone>())?;
        Ok(Memoire { espace: EspaceUtilisateur::creer()?, zones, debut_tas: 0, fin_tas: 0 })
    }

    /// Ajoute une zone, et y projette d'avance un cadre neuf, mis à zéro,
    /// par page : tout ce qu'un programme peut toucher est en place avant
    /// qu'il y touche (pas encore de pagination à la demande). En cas
    /// d'échec, rien n'est ajouté.
    pub fn ajouter_projetee(&mut self, zone: Zone) -> Result<(), Erreur> {
        self.zones.inserer(zone)?;
        for page in (zone.debut..zone.fin).step_by(PAGE as usize) {
            if let Err(e) = self.espace.projeter_neuve(page, zone.droits) {
                self.retirer(zone.debut, zone.fin)?;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Projette à `page` le cadre `cadre`, préparé à l'avance hors de tout
    /// verrou (voir CadreNeuf), avec les droits de sa zone.
    pub fn projeter(&mut self, page: u64, cadre: CadreNeuf) -> Result<(), Erreur> {
        let droits = self.zones.trouver(page).ok_or(Erreur::NonProjetee)?.droits;
        self.espace.projeter(page, cadre, droits).map(|_| ())
    }

    /// Retire [debut, fin[ (alignés) de la carte, puis des tables : brk qui
    /// recule. Échoue, sans rien changer, si une zone doit être coupée en
    /// deux et que la carte n'a plus de place.
    pub fn retirer(&mut self, debut: u64, fin: u64) -> Result<(), Erreur> {
        self.zones.retirer(debut, fin, |_| ())?;
        self.espace.retirer_plage(debut, fin);
        Ok(())
    }

    /// Donne les droits `droits` à [debut, fin[ (alignés, non vide) :
    /// mprotect. Toute la plage doit être dans des zones, sinon rien ne
    /// change (Linux rend alors ENOMEM).
    pub fn proteger(&mut self, debut: u64, fin: u64, droits: Droits) -> Result<(), Erreur> {
        if !self.zones.couverte(debut, fin) {
            return Err(Erreur::NonProjetee);
        }
        self.zones.changer(debut, fin, |z| z.droits = droits)?;
        self.espace.proteger_plage(debut, fin, droits);
        Ok(())
    }
}
