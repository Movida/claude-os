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

use crate::descripteurs::Fichier;
use crate::espace_utilisateur::{self, Erreur, EspaceUtilisateur};
use crate::vfs;
use crate::programmes::NomCourt;
use zones::{Droits, Nature, Sens, Zone, Zones};

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

/// Une zone de fichier apparaît (+1, une coupe) ou disparaît (-1, une
/// fusion, un retrait) : son fichier ouvert est tenu une fois de plus, ou
/// de moins (descripteurs.rs). Chaque zone de fichier tient ainsi son
/// fichier, qui survit à `close` tant qu'il est projeté (voir ../zones).
/// Appelée sous le verrou du processus : prend celui des fichiers, dans
/// l'ordre permis.
pub fn references(fichier: u32, delta: i32) {
    let f = Fichier::de(fichier);
    vfs::avec_systeme(|s, cadres| if delta > 0 { s.ouverts.prendre(f) } else { s.lacher(f, cadres) });
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
    /// Une page d'une projection de fichier au-delà de la fin du fichier
    /// (SIGBUS, BUS_ADRERR).
    HorsDuFichier,
    /// Une page de trou d'une projection de fichier, et plus de place dans
    /// le système de fichiers (SIGBUS, comme Linux).
    PlusDePlace,
}

impl Echec {
    /// Pour le message d'un programme arrêté (sans accents).
    pub fn texte(self) -> &'static str {
        match self {
            Echec::SansZone => "pas de zone",
            Echec::AccesInterdit => "acces interdit",
            Echec::PlusDeMemoire => "plus de memoire",
            Echec::HorsDuFichier => "au-dela de la fin du fichier",
            Echec::PlusDePlace => "plus de place pour le fichier",
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
    nom: NomCourt,
    nature: Nature,
    /// La zone projette un fichier : `nom` est le sien.
    fichier: bool,
    debut: u64,
    taille: u64,
}

impl fmt::Display for ZoneDuCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.nature {
            _ if self.fichier => write!(f, "{}", self.nom)?,
            Nature::Programme => write!(f, "{}", self.nom)?,
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
    pub nom: NomCourt,
}

impl Memoire {
    /// Une mémoire vide : pas de zones, un espace neuf. Le tas est placé
    /// par le chargeur.
    pub fn creer(nom: NomCourt) -> Result<Memoire, Erreur> {
        // La carte occupe d'emblée une page entière (85 zones), et
        // grandit en blocs de pages : le tas du noyau prend les blocs de
        // plus de 2 Kio directement à l'allocateur de pages, et les lui
        // rend à la destruction du programme. Une petite carte, elle,
        // viendrait des classes du tas (tas.rs), et partagerait sa page
        // avec d'autres objets du noyau pris pendant le programme (le nom
        // d'un fichier qu'il crée et laisse) : la page ne reviendrait
        // qu'avec le dernier d'entre eux, et la vérification « memoire
        // rendue » de chaque programme se tromperait.
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
        // Une zone de fichier dont la page n'est pas encore là : la page du
        // fichier, en lecture seule (entree_finale), tenue une fois de plus.
        // Puis, pour une écriture, la copie à l'écriture la remplace par une
        // page à lui (le `do_cow_fault` de Linux, en deux temps).
        if let Some(projection) = zone.fichier
            && !self.espace.occupee(page)
        {
            let index = zone.page_de(page).unwrap_or(0);
            let cadre = vfs::page_projetee(Fichier::de(projection.fichier), index)?;
            self.espace.poser_fichier(page, cadre, zone.droits).map_err(|_| Echec::PlusDeMemoire)?;
            if acces != Acces::Ecriture {
                return Ok(());
            }
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

    /// Retire [debut, fin[ (alignés) de la carte, puis des tables, dont
    /// celles devenues vides : munmap, brk qui recule. Échoue, sans rien
    /// changer, si une zone doit être coupée en deux et que la carte n'a
    /// plus de place (ENOMEM).
    pub fn retirer(&mut self, debut: u64, fin: u64) -> Result<(), Erreur> {
        self.zones.retirer(debut, fin, |_| (), &mut references)?;
        self.espace.retirer_plage(debut, fin, true);
        Ok(())
    }

    /// Où placer une nouvelle projection de `taille` octets (alignée, non
    /// nulle) : à l'adresse suggérée `suggestion` si elle est libre (écart
    /// de garde de la pile compris), sinon dans le trou le plus haut sous
    /// la base des projections, sinon dans le plus bas au-dessus du tiers
    /// des adresses. C'est la disposition de Linux sur x86_64
    /// (arch_get_unmapped_area_topdown) : les projections s'empilent sous
    /// la pile, vers le bas, loin du tas qui monte. La suggestion est
    /// arrondie à la page INFÉRIEURE, et ramenée à ADRESSE_MIN si elle est
    /// en dessous (round_hint_to_min), comme Linux (mesuré : 0x30000123
    /// donne 0x30000000, 0x1234 donne 0x10000).
    pub fn chercher_place(&self, taille: u64, suggestion: u64) -> Option<u64> {
        use espace_utilisateur::{ADRESSE_MAX, ADRESSE_MIN};
        if suggestion != 0 {
            let a = (suggestion & !(PAGE - 1)).max(ADRESSE_MIN);
            if a.checked_add(taille).is_some_and(|fin| fin <= ADRESSE_MAX) && self.zones.libre(a, a + taille, ECART_GARDE) {
                return Some(a);
            }
        }
        // Le TASK_UNMAPPED_BASE de Linux : le tiers des adresses.
        let base_ascendante = (ADRESSE_MAX / 3).next_multiple_of(PAGE);
        self.zones
            .trou(taille, ADRESSE_MIN, disposition().base_mmap, ECART_GARDE, Sens::DuHaut)
            .or_else(|| self.zones.trou(taille, base_ascendante, ADRESSE_MAX, ECART_GARDE, Sens::DuBas))
    }

    /// Ajoute la zone `zone` (mmap). Avec `remplacer` (MAP_FIXED), ce qui
    /// était à sa place est retiré d'abord. Tout ou rien : la place de deux
    /// zones (une coupée par le retrait, la nouvelle) est réservée avant de
    /// toucher à quoi que ce soit ; une carte à une zone du maximum est
    /// donc refusée même si les fusions l'auraient fait tenir. Linux,
    /// depuis 6.12, défait un retrait déjà fait ; c'est plus long à écrire
    /// et à relire.
    pub fn ajouter(&mut self, zone: Zone, remplacer: bool) -> Result<(), Erreur> {
        if remplacer {
            self.zones.reserver(2)?;
            self.retirer(zone.debut, zone.fin)?;
        }
        self.zones.inserer(zone, &mut references)?;
        Ok(())
    }

    /// Donne les droits `droits` à [debut, fin[ (alignés, non vide) :
    /// mprotect. Toute la plage doit être dans des zones, sinon rien ne
    /// change (Linux rend alors ENOMEM). Une zone privée qui devient
    /// inscriptible, sans MAP_NORESERVE, est promise comme par mmap : refusée
    /// si elle est à elle seule plus grande que toute la mémoire (Linux la
    /// marque alors VM_ACCOUNT, et ne la recompte plus ; sans ce drapeau, on
    /// recompte une zone rendue inscriptible deux fois, ce qui ne change
    /// rien tant qu'elle n'a pas, entre-temps, fusionné avec d'autres au-delà
    /// de la taille de la mémoire).
    pub fn proteger(&mut self, debut: u64, fin: u64, droits: Droits) -> Result<(), Erreur> {
        if !self.zones.couverte(debut, fin) {
            return Err(Erreur::NonProjetee);
        }
        let promise = |z: Zone| !droits.ecriture || z.droits.ecriture || z.drapeaux.sans_reserve || engagement_possible(z.taille());
        if !self.zones.morceaux(debut, fin).all(promise) {
            return Err(Erreur::PlusDeMemoire);
        }
        self.zones.changer(debut, fin, |z| z.droits = droits, &mut references)?;
        self.espace.proteger_plage(debut, fin, droits);
        Ok(())
    }

    /// Retire les pages de [debut, fin[ sans toucher aux zones
    /// (MADV_DONTNEED) : elles se reliront à zéro, ou depuis le fichier
    /// projeté. Les tables restent, la zone aussi. Sans effet sur un segment
    /// du programme copié sans fichier derrière (voir madvise, dans
    /// linux.rs).
    pub fn oublier(&mut self, debut: u64, fin: u64) {
        for z in self.zones.morceaux(debut, fin).filter(|z| z.fichier.is_some() || z.nature != Nature::Programme) {
            self.espace.retirer_plage(z.debut, z.fin, false);
        }
    }

    /// La zone qui contient `adresse`, pour un message.
    pub fn zone_du_code(&self, adresse: u64) -> Option<ZoneDuCode> {
        let z = self.zones.trouver(adresse)?;
        // Le nom du fichier projeté, s'il y en a un (sous le verrou des
        // fichiers, pris après celui du processus).
        let nom = z.fichier.map_or(self.nom, |p| vfs::avec_systeme(|s, _| s.ouverts.fichier(Fichier::de(p.fichier)).nom));
        Some(ZoneDuCode { nom, nature: z.nature, fichier: z.fichier.is_some(), debut: z.debut, taille: z.taille() })
    }

    /// La taille de toutes ses zones, en octets (la « mémoire virtuelle »,
    /// le total-vm de Linux).
    pub fn taille_virtuelle(&self) -> u64 {
        self.zones.zones().iter().map(Zone::taille).sum()
    }
}
