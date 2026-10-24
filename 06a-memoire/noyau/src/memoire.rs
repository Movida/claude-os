//! La mémoire d'un programme : sa carte des zones (ce qu'il a le droit de
//! toucher, ../zones), ses tables de pages (ce qui est en place,
//! espace_utilisateur.rs) et son tas. C'est la mm_struct de Linux.
//!
//! La carte fait foi : une page n'est projetée que dans une zone, avec les
//! droits de sa zone. Toute opération (brk, mprotect) change d'abord la
//! carte, qui peut refuser (trop de zones, plus de mémoire) sans rien avoir
//! changé ; puis seulement les tables, ce qui ne peut plus échouer.
//!
//! Les tables se remplissent À LA FAUTE (la pagination à la demande) : une
//! zone neuve n'a aucune page. Le premier accès à une page fait une faute
//! de page ; si l'adresse est dans une zone qui permet cet accès, le noyau
//! donne la page (`servir`) et le programme reprend son instruction, sans
//! rien savoir. Une réservation de 8 Gio ne coûte donc que ce que le
//! programme touche vraiment.
//!
//! La politique de la mémoire est celle de Linux (choix de conception) :
//!   - PROMETTRE plus qu'on n'a (le « surengagement ») : une zone n'est
//!     pas de la mémoire, seulement le droit d'en demander. Une demande
//!     n'est refusée que si elle est manifestement impossible : à elle
//!     seule plus grande que toute la mémoire de la machine
//!     (`engagement_possible`, l'heuristique OVERCOMMIT_GUESS, le réglage
//!     par défaut de Linux) ;
//!   - garder une RÉSERVE au noyau : les pages et les tables d'un
//!     programme ne sont prises que s'il reste plus que min_free_kbytes
//!     (pages.rs) ;
//!   - quand une page manque vraiment à la faute, TUER le programme
//!     (SIGKILL, le tueur OOM, tache::arreter_plus_de_memoire). Linux
//!     choisit le plus gros processus ; avec un seul programme, c'est lui.
//! Options écartées :
//!   - un budget fixe par programme (celui de l'étape 5 : 256 Mio, ou la
//!     moitié de la mémoire libre) : `claude` occupe 169 Mo à l'accueil et
//!     en réserve 9 Gio, un budget le bloquerait ; et Linux ne plafonne pas
//!     un processus par défaut (RLIMIT_AS et RLIMIT_DATA sont infinis) ;
//!   - tout compter, sans promettre (OVERCOMMIT_NEVER, `vm.overcommit_memory
//!     = 2`) : les 8 Gio réservés par JavaScriptCore seraient refusés sur
//!     toute machine ordinaire.

use core::fmt;

use crate::espace_utilisateur::{self, Erreur, EspaceUtilisateur};
use crate::programmes::Nom;
use zones::{Droits, Nature, Zone, Zones};

const PAGE: u64 = 4096;

/// La taille maximale de la pile : le RLIMIT_STACK de Linux par défaut,
/// 8 Mio. Mesuré sur l'hôte : une récursion de 7 Mio passe, une de 9 Mio
/// est arrêtée par SIGSEGV.
pub const PILE_MAX: u64 = 8 << 20;
/// L'écart de garde sous la pile : aucune zone accessible ne peut
/// s'installer à moins de 1 Mio sous elle, pour qu'une pile qui déborde
/// fasse une faute au lieu d'écrire en silence dans une autre zone (le
/// stack_guard_gap de Linux, 256 pages depuis 2017 et l'attaque « Stack
/// Clash »).
pub const ECART_GARDE: u64 = 1 << 20;
/// Ce qu'on donne à la pile en plus de ce qu'occupent arguments et
/// environnement au lancement : 128 Kio (le stack_expand de
/// setup_arg_pages, dans Linux). Elle grandit ensuite à la faute.
pub const PILE_INITIALE: u64 = 128 << 10;

/// Où se trouve quoi dans l'espace d'un programme. Une seule fonction le
/// calcule (l'arch_pick_mmap_layout de Linux) : c'est là que viendra se
/// brancher l'aléa de l'ASLR (6m). D'ici là, les adresses sont fixes, ce
/// qui aide à mettre ld-linux et `claude` au point (les développeurs de
/// Linux font de même, avec `setarch -R`).
pub struct Disposition {
    /// Le sommet de la pile : la fin des adresses permises.
    pub sommet_pile: u64,
    /// Le haut de la région des projections (mmap), et la limite des
    /// segments du programme : 128 Mio sous le sommet de la pile. Linux
    /// laisse sous la pile sa taille maximale plus l'écart de garde, et au
    /// moins 128 Mio : ici 8 + 1 Mio, donc 128 Mio. La pile peut toujours
    /// grandir jusqu'à sa limite sans rencontrer personne.
    pub base_mmap: u64,
}

pub const fn disposition() -> Disposition {
    let sommet_pile = espace_utilisateur::ADRESSE_MAX;
    let ecart = PILE_MAX + ECART_GARDE;
    let ecart = if ecart < 128 << 20 { 128 << 20 } else { ecart };
    Disposition { sommet_pile, base_mmap: sommet_pile - ecart }
}

/// Une zone privée inscriptible de `octets` octets peut-elle être promise ?
/// Seulement si elle ne dépasse pas, à elle seule, toute la mémoire de la
/// machine (le __vm_enough_memory de Linux, en OVERCOMMIT_GUESS, sans
/// mémoire d'échange). Le reste est promis sans être compté : la sonde
/// l'a vérifié sous Linux, deux fois la mémoire en lecture et écriture est
/// refusé, la même chose sans réservation (MAP_NORESERVE), ou en lecture
/// seule, est accepté.
pub fn engagement_possible(octets: u64) -> bool {
    octets / PAGE <= crate::pages::total() as u64
}

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

/// L'accès qui a fait faute, d'après le code d'erreur de la faute.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Acces {
    Lecture,
    Ecriture,
    Execution,
}

/// Pourquoi une faute n'a pas pu être servie.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Echec {
    /// Aucune zone à cette adresse (le SEGV_MAPERR de Linux).
    SansZone,
    /// Une zone, mais qui ne permet pas cet accès (SEGV_ACCERR).
    AccesInterdit,
    /// Plus de mémoire pour la page ou pour une table.
    PlusDeMemoire,
}

impl Echec {
    /// Pour le message d'un programme arrêté (sans accents).
    pub fn texte(self) -> &'static str {
        match self {
            Echec::SansZone => "pas de zone",
            Echec::AccesInterdit => "acces interdit",
            Echec::PlusDeMemoire => "plus de memoire",
        }
    }
}

/// La zone où était une adresse (RIP, pour le message d'un programme
/// arrêté), comme Linux l'écrit : « bonjour-c[401000+9a000] », le nom, le
/// début de la zone et sa taille. C'est souvent ce qui dit le plus vite
/// où chercher : dans le programme, dans sa pile, dans du code compilé à
/// la volée...
#[derive(Clone, Copy)]
pub struct ZoneDuCode {
    nom: &'static [u8],
    nature: Nature,
    debut: u64,
    taille: u64,
}

impl fmt::Display for ZoneDuCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.nature {
            Nature::Programme => write!(f, "{}", Nom(self.nom))?,
            Nature::Tas => f.write_str("[tas]")?,
            Nature::Pile => f.write_str("[pile]")?,
            Nature::Anonyme => f.write_str("[anonyme]")?,
        }
        write!(f, "[{:x}+{:x}]", self.debut, self.taille)
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
    /// Le nom du programme, pour les messages.
    pub nom: &'static [u8],
}

impl Memoire {
    /// Une mémoire vide : pas de zones, un espace neuf. Le tas est placé
    /// par le chargeur.
    pub fn creer(nom: &'static [u8]) -> Result<Memoire, Erreur> {
        // La carte occupe d'emblée une page entière (170 zones), et
        // grandit en blocs de pages : le tas du noyau prend les blocs de
        // plus de 2 Kio directement à l'allocateur de pages, et les lui
        // rend à la destruction du programme. Une petite carte, elle,
        // viendrait des classes du tas, qui gardent leurs pages même
        // vides (tas.rs) : la mémoire du premier programme qui atteint une
        // taille de carte ne reviendrait jamais à l'allocateur de pages, et
        // la vérification « memoire rendue » ne pourrait plus rien dire.
        let zones = Zones::avec_capacite(PAGE as usize / size_of::<Zone>())?;
        Ok(Memoire { espace: EspaceUtilisateur::creer()?, zones, debut_tas: 0, fin_tas: 0, nom })
    }

    /// Sert une faute de page à `adresse`, pour l'accès `acces` : la page
    /// est mise en place si une zone la permet (voir
    /// EspaceUtilisateur::servir), et l'instruction peut reprendre. Sous la
    /// pile, à moins de PILE_MAX de son sommet, la pile s'étend d'abord
    /// jusqu'à la page (le expand_stack de Linux).
    ///
    /// Le contrôle des droits : une écriture demande le droit d'écrire, une
    /// exécution celui d'exécuter, une lecture un droit quelconque (x86 ne
    /// sait pas interdire la lecture d'une page présente).
    pub fn servir(&mut self, adresse: u64, acces: Acces) -> Result<(), Echec> {
        let page = adresse & !(PAGE - 1);
        if self.zones.trouver(page).is_none() && !self.zones.etendre_pile(page, PILE_MAX, ECART_GARDE) {
            return Err(Echec::SansZone);
        }
        let zone = *self.zones.trouver(page).ok_or(Echec::SansZone)?;
        let permis = match acces {
            Acces::Lecture => zone.droits.accessible(),
            Acces::Ecriture => zone.droits.ecriture,
            Acces::Execution => zone.droits.execution,
        };
        if !permis {
            return Err(Echec::AccesInterdit);
        }
        self.espace.servir(page, zone.droits, acces == Acces::Ecriture).map_err(|_| Echec::PlusDeMemoire)
    }

    /// Écrit `octets` à l'adresse `adresse` du programme, par la projection
    /// directe des cadres, en faisant d'abord venir chaque page (une page
    /// neuve, à lui) : le noyau qui remplit les segments du programme ou sa
    /// pile initiale. Les pages doivent être dans des zones, mais leurs
    /// droits ne comptent pas (le noyau remplit ainsi du code en lecture
    /// seule pour le programme).
    pub fn ecrire(&mut self, adresse: u64, octets: &[u8]) -> Result<(), Erreur> {
        let fin = adresse.checked_add(octets.len() as u64).ok_or(Erreur::AdresseInterdite)?;
        let mut page = adresse & !(PAGE - 1);
        while page < fin {
            let droits = self.zones.trouver(page).ok_or(Erreur::NonProjetee)?.droits;
            self.espace.servir(page, droits, true)?;
            page += PAGE;
        }
        self.espace.ecrire(adresse, octets)
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

    /// La zone qui contient `adresse`, pour un message.
    pub fn zone_du_code(&self, adresse: u64) -> Option<ZoneDuCode> {
        let z = self.zones.trouver(adresse)?;
        Some(ZoneDuCode { nom: self.nom, nature: z.nature, debut: z.debut, taille: z.taille() })
    }

    /// La taille de toutes ses zones, en octets (la « mémoire virtuelle »,
    /// le total-vm de Linux).
    pub fn taille_virtuelle(&self) -> u64 {
        self.zones.zones().iter().map(Zone::taille).sum()
    }
}
