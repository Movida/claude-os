//! La mémoire d'un programme : sa carte des zones (ce qu'il a le droit de
//! toucher, ../zones), ses tables de pages (ce qui est en place,
//! espace_utilisateur.rs) et son tas. C'est la mm_struct de Linux.
//!
//! Depuis 6i, elle est sous un verrou qui dort, en lecture et en écriture
//! (le `mmap_lock` de Linux, processus.rs) : les fautes de page la LISENT
//! (`servir`, `&self`), et peuvent être plusieurs à la fois ; mmap,
//! munmap, mprotect, brk, madvise la CHANGENT (`&mut self`), seuls. Les
//! tables de pages, que les fautes changent aussi, ont leur propre verrou
//! court (`espace`, le `page_table_lock`), que les écrivains n'ont pas à
//! prendre (`Verrou::get_mut`) : un munmap de centaines de Mio rend ses
//! pages interruptions actives.
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
//!     choisit le plus gros processus ; nous, celui qui faute. Avec un seul
//!     programme à la fois, c'était le même ; depuis que plusieurs tournent
//!     ensemble (`&`, 6e), un petit peut payer pour un gros : un écart, noté
//!     dans « Reste à faire ».
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
use crate::espace_utilisateur::{self, Compteurs, Erreur, EspaceUtilisateur, Servi};
use crate::partage::Arc;
use crate::verrou::Verrou;
use crate::vfs;
use crate::programmes::NomCourt;
use zones::{Drapeaux, Droits, Nature, Sens, Zone, Zones};

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
/// brancher l'aléa de l'ASLR (6n). D'ici là, les adresses sont fixes, ce
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
    /// Où vont les exécutables ET_DYN qui ont un interpréteur (les PIE),
    /// et le tas de ceux qui n'en ont pas (static-pie, ld-linux lancé
    /// directement) : les deux tiers des adresses, l'ELF_ET_DYN_BASE de
    /// Linux (DEFAULT_MAP_WINDOW / 3 * 2, soit 0x555555554aaa : ni arrondi
    /// à la page, Linux l'arrondit à l'usage). Loin sous les projections,
    /// loin au-dessus des ET_EXEC (0x400000) : un programme et ld-linux
    /// lancé à la main ne se marchent pas dessus.
    pub base_pie: u64,
}

pub const fn disposition() -> Disposition {
    let sommet_pile = espace_utilisateur::ADRESSE_MAX;
    let ecart = PILE_MAX + ECART_GARDE;
    let ecart = if ecart < 128 << 20 { 128 << 20 } else { ecart };
    Disposition { sommet_pile, base_mmap: sommet_pile - ecart, base_pie: sommet_pile / 3 * 2 }
}

/// Une zone de ces droits et drapeaux compte-t-elle dans RLIMIT_DATA ?
/// Inscriptible, privée (toutes le sont chez nous), et pas la pile
/// (`is_data_mapping` : VM_WRITE sans VM_SHARED ni VM_STACK).
pub fn est_des_donnees(droits: Droits, drapeaux: Drapeaux) -> bool {
    droits.ecriture && !drapeaux.vers_le_bas
}

/// Les limites de la mémoire d'un programme : RLIMIT_AS (la courante), et
/// RLIMIT_DATA (la courante et la maximale).
#[derive(Clone, Copy)]
pub struct Limites {
    pub espace: u64,
    pub donnees: (u64, u64),
}

impl Limites {
    /// Celles du processus courant.
    pub fn du_processus() -> Limites {
        crate::processus::avec(|p| Limites {
            espace: p.courante(crate::processus::RLIMIT_AS),
            donnees: p.limites[crate::processus::RLIMIT_DATA],
        })
    }
}

/// La place que permettent RLIMIT_AS et RLIMIT_DATA (`may_expand_vm`) :
/// `octets` de plus (de données si `donnees`) tiennent-ils à côté de la
/// mémoire du programme ? Une RLIMIT_DATA à 0 laisse passer jusqu'à la
/// limite maximale (le « Workaround for Valgrind » de Linux : Valgrind la
/// met à 0 pour lui-même). Le même nombre pour les deux comptes : pour
/// MAP_FIXED, ce qui s'ajoute moins TOUT ce qui est remplacé
/// (`pglen - nr_pages`), données ou non.
pub fn place_permise(m: &Memoire, octets: u64, donnees: bool, l: Limites) -> bool {
    if m.taille_virtuelle().saturating_add(octets) > l.espace {
        return false;
    }
    let apres = m.taille_donnees().saturating_add(octets);
    !donnees || apres <= l.donnees.0 || (l.donnees.0 == 0 && apres <= l.donnees.1)
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
/// Appelée mémoire tenue en écriture : prend celui des fichiers, dans
/// l'ordre permis (processus.rs).
pub fn references(fichier: u32, delta: i32) {
    let f = Fichier::de(fichier);
    vfs::avec_systeme(|s, cadres| if delta > 0 { s.ouverts.prendre(f) } else { s.lacher(f, cadres) });
}

impl Drop for Memoire {
    /// La fin de la mémoire d'un programme : chaque zone de fichier lâche
    /// son fichier ouvert (ses pages sont rendues par l'espace, qui
    /// disparaît ensuite).
    fn drop(&mut self) {
        for z in self.zones.zones() {
            if let Some(p) = z.fichier {
                references(p.fichier, -1);
            }
        }
    }
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

/// Les cadres qu'un lot de munmap ou de madvise garde avant de vider les
/// TLB et de les rendre : 4096 (32 Kio), un vidage par 16 Mio rendus.
const GRAND_LOT: usize = 4096;

pub struct Memoire {
    /// Les tables de pages, sous leur verrou court (le `page_table_lock`
    /// de Linux) : une faute, qui ne tient la mémoire qu'en lecture, le
    /// prend pour poser son entrée ; qui la tient en écriture y accède sans
    /// lui (`get_mut`). Un verrou pour tout l'espace ; Linux en a un par
    /// table de dernier niveau (les « split PTE ptlocks »), pour que des
    /// fautes sur plusieurs processeurs ne s'attendent pas. Mesuré en 6j
    /// pendant `claude -p` sur quatre processeurs (`make verrous-claude-p`,
    /// chaque prise comptée depuis la relecture de 6j) : le plus attendu de
    /// tous les verrous courts, 600 à 730 attentes sur 50 000 prises par
    /// lancement (1,2 à 1,5 %), 166 µs au plus : trop peu pour un verrou par
    /// table ; à remesurer quand `claude` travaillera pour de bon (6l, le
    /// shell).
    pub espace: Verrou<EspaceUtilisateur>,
    /// Les compteurs de l'espace (ses pages en place, ses tables, son pic),
    /// les mêmes que derrière le verrou : lisibles ici sans lui (statm, le
    /// tueur OOM ; espace_utilisateur.rs, `Compteurs`).
    compteurs: Arc<Compteurs>,
    pub zones: Zones,
    /// Le début du tas : la page qui suit le dernier segment (le .bss).
    pub debut_tas: u64,
    /// La fin du tas, à l'octet près (le « program break » de brk). La
    /// zone du tas va de son début à la page qui contient sa fin.
    pub fin_tas: u64,
    /// Le nom du programme, pour les messages.
    pub nom: NomCourt,
    /// Le début et la fin de son code : du plus petit début au plus grand
    /// bout du fichier de ses segments exécutables (les `start_code` et
    /// `end_code` de Linux), pour /proc/<pid>/statm. (0, 0) sans code.
    pub code: (u64, u64),
    /// Le début et la fin de ses données, comme Linux (load_elf_binary) :
    /// `start_data` le plus grand p_vaddr de ses segments, `end_data` le
    /// plus grand p_vaddr + p_filesz ; RLIMIT_DATA y compte, avec le tas
    /// (`check_data_rlimit`, brk). (0, 0) avant le chargement.
    pub donnees: (u64, u64),
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
        let espace = EspaceUtilisateur::creer()?;
        let compteurs = espace.compteurs().clone();
        Ok(Memoire { espace: Verrou::new(espace), compteurs, zones, debut_tas: 0, fin_tas: 0, nom, code: (0, 0), donnees: (0, 0) })
    }

    /// Les tables de pages, sans leur verrou : qui a `&mut Memoire` (la
    /// mémoire en écriture, ou le chargeur qui la construit) les a seul.
    pub fn tables(&mut self) -> &mut EspaceUtilisateur {
        self.espace.get_mut()
    }

    /// Sert une faute de page à `adresse`, pour l'accès `acces`, mémoire
    /// tenue en lecture : la page est mise en place si une zone la permet
    /// (voir EspaceUtilisateur::servir), et l'instruction peut reprendre.
    /// Hors de toute zone : `SansZone`, sans étendre la pile (qui change la
    /// carte : `etendre_pile`, en écriture ; processus::servir_faute choisit).
    ///
    /// Le contrôle des droits : une écriture demande le droit d'écrire, une
    /// exécution celui d'exécuter, une lecture un droit quelconque (x86 ne
    /// sait pas interdire la lecture d'une page présente).
    ///
    /// Ce qui peut attendre ou prendre du temps se fait hors du verrou des
    /// tables (comme Linux) : la page du fichier, prise au tmpfs et tenue ;
    /// la page neuve d'une écriture, mise à zéro, seulement si l'entrée en
    /// demande une. Sous le verrou, la décision est revérifiée (le
    /// `pte_same` de Linux) : un autre fil a pu fauter à la même page
    /// entre-temps (sa page reste, la nôtre est rendue), ou une troncature
    /// retirer la page du fichier (on recommence par le fichier : SIGBUS
    /// s'il est raccourci, jamais une page neuve à sa place).
    pub fn servir(&self, adresse: u64, acces: Acces) -> Result<(), Echec> {
        let page = adresse & !(PAGE - 1);
        let zone = *self.zones.trouver(page).ok_or(Echec::SansZone)?;
        let permis = match acces {
            Acces::Lecture => zone.droits.accessible(),
            Acces::Ecriture => zone.droits.ecriture,
            Acces::Execution => zone.droits.execution,
        };
        if !permis {
            return Err(Echec::AccesInterdit);
        }
        let ecriture = acces == Acces::Ecriture;
        let mut neuve = None;
        let resultat = loop {
            match self.poser_page_du_fichier(page, &zone) {
                Ok(true) if !ecriture => break Ok(()),
                Ok(_) => {}
                Err(e) => break Err(e),
            }
            // Le verrou des tables est rendu à la fin de cette ligne (la
            // garde est un temporaire de l'appel, pas du `match` : un
            // temporaire du `match` vivrait jusqu'à sa fin, et le lot d'un
            // remplacement se viderait verrou tenu).
            let servi = self.espace.verrouiller().servir(page, zone.droits, ecriture, zone.fichier.is_some(), &mut neuve);
            match servi {
                Ok(Servi::Fait) => break Ok(()),
                // L'entrée du fichier a disparu (raccourci pendant la
                // faute), ou un autre fil remplace la page : on recommence
                // par le fichier (l'autre finit en quelques microsecondes,
                // préemption coupée).
                Ok(Servi::ARefaire) => core::hint::spin_loop(),
                Ok(Servi::PageNeuve) => match espace_utilisateur::cadre_neuf() {
                    Some(c) => neuve = Some(c),
                    None => break Err(Echec::PlusDeMemoire),
                },
                // La copie à l'écriture : le verrou des tables est rendu
                // (la garde était celle de l'appel), l'ancienne traduction
                // vidée sur tous les processeurs qui ont l'espace, puis la
                // nouvelle page posée si l'entrée n'a pas changé (sinon on
                // recommence : espace_utilisateur.rs).
                Ok(Servi::Remplacement(mut lot, marque)) => {
                    // Préemption coupée de la marque à son remplacement : une
                    // faute d'un autre fil qui la trouve recommence tant
                    // qu'elle est là, et une préemption ici l'y laisserait
                    // une tranche entière (la relecture de 6j). Le vidage
                    // attend les autres processeurs interruptions actives.
                    let r = crate::processeur::sans_preemption(|| {
                        lot.vider();
                        self.espace.verrouiller().remplacer(page, zone.droits, &mut neuve, marque)
                    });
                    match r {
                        Ok(Servi::Fait) => break Ok(()),
                        Ok(_) => {}
                        Err(_) => break Err(Echec::PlusDeMemoire),
                    }
                }
                Err(_) => break Err(Echec::PlusDeMemoire),
            }
        };
        if let Some(c) = neuve {
            espace_utilisateur::rendre_cadre(c);
        }
        resultat
    }

    /// Étend la pile jusqu'à la page de `adresse` (le `expand_stack` de
    /// Linux), mémoire tenue en écriture : vrai si la page est maintenant
    /// dans la zone de la pile. Sous la pile ; la pile pas plus grande que
    /// `pile_max` (RLIMIT_STACK, `acct_stack_growth`), le programme pas plus
    /// grand que `espace` (RLIMIT_AS) ; et pas à moins de l'écart de garde
    /// d'une autre zone. (PILE_MAX, 8 Mio, la limite par défaut, ne sert
    /// plus qu'à placer les projections sous la pile, au lancement.)
    pub fn etendre_pile(&mut self, adresse: u64, pile_max: u64, espace: u64) -> bool {
        let page = adresse & !(PAGE - 1);
        if self.zones.trouver(page).is_some() {
            return true;
        }
        let Some(pile) = self.zones.suivante(page).copied() else { return false };
        if pile.debut > page && self.taille_virtuelle().saturating_add(pile.debut - page) > espace {
            return false;
        }
        self.zones.etendre_pile(page, pile_max, ECART_GARDE)
    }

    /// La zone qui suit `adresse` grandit-elle vers le bas (la pile) ? Une
    /// faute hors de toute zone juste sous elle peut alors l'étendre : il
    /// faut la mémoire en écriture (le test `VM_GROWSDOWN` de
    /// `lock_mm_and_find_vma`, qui évite de la prendre pour une simple
    /// faute hors des zones).
    pub fn pile_au_dessus(&self, adresse: u64) -> bool {
        self.zones.suivante(adresse).is_some_and(|z| z.drapeaux.vers_le_bas && z.debut > adresse)
    }

    /// Dans une zone de fichier dont la page n'est pas encore là : la page
    /// du fichier, en lecture seule (entree_finale), tenue par l'entrée.
    /// Rend vrai si elle a été posée ; faux si l'entrée était déjà occupée
    /// (avant, ou par un autre fil entre-temps : `servir` refait alors
    /// l'entrée, voir EspaceUtilisateur::servir). Pour une écriture, la
    /// copie à l'écriture la remplacera ensuite par une page à lui (le
    /// `do_cow_fault` de Linux, en deux temps).
    ///
    /// La page vient tenue du tmpfs (vfs::page_projetee) ; une fois
    /// l'entrée posée, sous le verrou des tables, on revérifie qu'elle est
    /// toujours celle du fichier : sinon le fichier a été raccourci pendant
    /// la faute, l'entrée est retirée et tout recommence (la faute rendra
    /// alors `HorsDuFichier`, SIGBUS, comme le veut la troncature). Le
    /// verrou des fichiers est pris SOUS celui des tables : jamais l'inverse
    /// (une troncature lit les zones, puis prend celui des tables pour
    /// retirer les pages, sans tenir celui des fichiers).
    fn poser_page_du_fichier(&self, page: u64, zone: &Zone) -> Result<bool, Echec> {
        let Some(projection) = zone.fichier else { return Ok(false) };
        let index = zone.page_de(page).unwrap_or(0);
        let fichier = Fichier::de(projection.fichier);
        loop {
            if self.espace.verrouiller().occupee(page) {
                return Ok(false);
            }
            let cadre = vfs::page_projetee(fichier, index)?;
            let mut espace = self.espace.verrouiller();
            match espace.poser_fichier(page, cadre, zone.droits) {
                Ok(()) if vfs::page_encore_projetable(fichier, index, cadre) => return Ok(true),
                // Raccourci entre-temps : l'entrée est retirée (elle tenait
                // le cadre), et on recommence. Le lot se vide une fois le
                // verrou des tables rendu (espace_utilisateur.rs).
                Ok(()) => {
                    let mut lot = espace_utilisateur::Lot::new(&espace);
                    espace.retirer_plage(page, page + PAGE, false, &mut lot);
                    drop(espace);
                    drop(lot);
                }
                Err(Erreur::DejaProjetee) => {
                    crate::pages::lacher(cadre);
                    return Ok(false);
                }
                Err(_) => {
                    crate::pages::lacher(cadre);
                    return Err(Echec::PlusDeMemoire);
                }
            }
        }
    }

    /// Écrit `octets` à l'adresse `adresse` du programme, par la projection
    /// directe des cadres, en faisant d'abord venir chaque page (une page à
    /// lui, copie de celle du fichier dans une zone de fichier) : le noyau
    /// qui remplit la pile initiale, ou met à zéro la fin d'un segment
    /// (padzero, chargeur_elf.rs). Les pages doivent être dans des zones,
    /// mais leurs droits ne comptent pas.
    pub fn ecrire(&mut self, adresse: u64, octets: &[u8]) -> Result<(), Erreur> {
        let fin = adresse.checked_add(octets.len() as u64).ok_or(Erreur::AdresseInterdite)?;
        let mut page = adresse & !(PAGE - 1);
        while page < fin {
            let zone = *self.zones.trouver(page).ok_or(Erreur::NonProjetee)?;
            // La page d'un fichier d'abord, puis sa copie : on n'écrit
            // jamais dans le fichier (padzero).
            self.poser_page_du_fichier(page, &zone).map_err(|e| match e {
                Echec::PlusDeMemoire => Erreur::PlusDeMemoire,
                _ => Erreur::NonProjetee,
            })?;
            // Seul à tenir la mémoire : rien ne change entre deux essais.
            let mut neuve = None;
            let r = (|| -> Result<(), Erreur> {
                loop {
                    match self.tables().servir(page, zone.droits, true, zone.fichier.is_some(), &mut neuve)? {
                        Servi::Fait => return Ok(()),
                        Servi::PageNeuve => neuve = Some(espace_utilisateur::cadre_neuf().ok_or(Erreur::PlusDeMemoire)?),
                        Servi::ARefaire => return Err(Erreur::NonProjetee),
                        Servi::Remplacement(mut lot, marque) => {
                            lot.vider();
                            match self.tables().remplacer(page, zone.droits, &mut neuve, marque)? {
                                Servi::Fait => return Ok(()),
                                _ => return Err(Erreur::NonProjetee),
                            }
                        }
                    }
                }
            })();
            // Une page préparée et pas posée (une erreur) est rendue, comme
            // dans `servir` (la relecture de 6j).
            if let Some(c) = neuve {
                espace_utilisateur::rendre_cadre(c);
            }
            r?;
            page += PAGE;
        }
        self.tables().ecrire(adresse, octets)
    }

    /// Retire [debut, fin[ (alignés) de la carte, puis des tables, dont
    /// celles devenues vides : brk qui recule, MAP_FIXED, la pile d'un
    /// programme qu'on raccourcit (mémoire tenue en écriture). munmap, lui,
    /// fait les deux temps lui-même, la carte en écriture et les tables en
    /// lecture (linux.rs). Échoue, sans rien changer, si une zone doit être
    /// coupée en deux et que la carte n'a plus de place (ENOMEM).
    pub fn retirer(&mut self, debut: u64, fin: u64) -> Result<(), Erreur> {
        self.retirer_zones(debut, fin)?;
        self.rendre_pages(debut, fin);
        Ok(())
    }

    /// Le premier temps : retire [debut, fin[ de la carte (mémoire tenue en
    /// écriture : la carte change). Dès lors, aucune faute ne peut plus y
    /// poser de page : il n'y a plus de zone, SIGSEGV.
    pub fn retirer_zones(&mut self, debut: u64, fin: u64) -> Result<(), Erreur> {
        self.zones.retirer(debut, fin, |_| (), &mut references)?;
        Ok(())
    }

    /// Le second temps : rend les pages et les tables de [debut, fin[, dont
    /// les zones ont été retirées. La mémoire tenue en LECTURE suffit (6j) :
    /// les tables sont sous leur verrou, par tranches, chaque lot vidé sans
    /// lui (espace_utilisateur.rs), et les fautes des autres fils, ailleurs,
    /// continuent pendant ce temps ; un grand lot, pour vider les TLB des
    /// autres processeurs le moins souvent possible. C'est le
    /// `do_vmi_align_munmap` de Linux : les zones détachées en écriture,
    /// `mmap_write_downgrade`, puis `unmap_region`.
    pub fn rendre_pages(&self, debut: u64, fin: u64) {
        EspaceUtilisateur::retirer_par_tranches(&self.espace, debut, fin, true, GRAND_LOT);
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
        self.chercher_place_alignee(taille, suggestion, PAGE)
    }

    /// La même, à une adresse multiple de `alignement` (une puissance de
    /// deux, une page au moins) : pour un exécutable ET_DYN qui demande un
    /// alignement (son `p_align`, 6c). Une suggestion qui n'est pas alignée
    /// est ignorée. (Linux, pour un static-pie aligné, projette l'image où
    /// mmap la met, puis arrondit l'adresse en dessous et la reprojette en
    /// MAP_FIXED_NOREPLACE, ce qui échoue si l'arrondi tombe sur une autre
    /// zone ; chercher d'emblée un trou aligné, comme le fait mmap pour les
    /// grandes pages, ne peut pas échouer ainsi.)
    pub fn chercher_place_alignee(&self, taille: u64, suggestion: u64, alignement: u64) -> Option<u64> {
        use espace_utilisateur::{ADRESSE_MAX, ADRESSE_MIN};
        if suggestion != 0 {
            let a = (suggestion & !(PAGE - 1)).max(ADRESSE_MIN);
            if a % alignement == 0
                && a.checked_add(taille).is_some_and(|fin| fin <= ADRESSE_MAX)
                && self.zones.libre(a, a + taille, ECART_GARDE)
            {
                return Some(a);
            }
        }
        // Le TASK_UNMAPPED_BASE de Linux : le tiers des adresses.
        let base_ascendante = (ADRESSE_MAX / 3).next_multiple_of(PAGE);
        self.zones
            .trou(taille, ADRESSE_MIN, disposition().base_mmap, ECART_GARDE, alignement, Sens::DuHaut)
            .or_else(|| self.zones.trou(taille, base_ascendante, ADRESSE_MAX, ECART_GARDE, alignement, Sens::DuBas))
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
    /// mprotect. Zone par zone depuis `debut`, comme Linux
    /// (`do_mprotect_pkey`) : au premier trou, NonProjetee (ENOMEM), et les
    /// zones d'avant gardent leurs nouveaux droits ; de même pour une zone
    /// privée qui devient inscriptible, sans MAP_NORESERVE, jamais promise,
    /// et dont la partie changée ne peut pas l'être comme par mmap
    /// (PlusDeMemoire : plus grande à elle seule que toute la mémoire). Une
    /// zone promise le reste (VM_ACCOUNT, `mprotect_fixup`) : elle n'est plus
    /// recomptée. Une zone rendue inscriptible : PlusDeMemoire si `limites`
    /// refusent ses nouveaux droits et pas les anciens (`mprotect_fixup`,
    /// deux `may_expand_vm`) : une zone qui devient des données au-delà de
    /// RLIMIT_DATA, sauf si RLIMIT_AS est déjà dépassée (les deux refusent).
    /// Jusqu'aux soldes d'avant 6k, un trou ne laissait rien
    /// changer, et une zone rendue inscriptible deux fois était recomptée
    /// (refusée si elle avait fusionné entre-temps au-delà de la taille de la
    /// mémoire) : deux écarts sans raison.
    pub fn proteger(&mut self, debut: u64, fin: u64, droits: Droits, limites: Limites) -> Result<(), Erreur> {
        let mut ici = debut;
        while ici < fin {
            let z = *self.zones.trouver(ici).ok_or(Erreur::NonProjetee)?;
            let bout = z.fin.min(fin);
            // Rendue inscriptible : les limites, comme `mprotect_fixup`.
            let n = bout - ici;
            if droits.ecriture
                && !place_permise(self, n, est_des_donnees(droits, z.drapeaux), limites)
                && place_permise(self, n, est_des_donnees(z.droits, z.drapeaux), limites)
            {
                return Err(Erreur::PlusDeMemoire);
            }
            // À promettre : rendue inscriptible, jamais promise, sans
            // MAP_NORESERVE ; la partie changée seulement (`nrpages`). Une
            // zone promise le reste, même jamais écrite. Linux retire
            // VM_ACCOUNT à une zone anonyme sans `anon_vma` (jamais écrite)
            // qui perd l'écriture, et la recompte ensuite : un écart voulu,
            // nos zones ne gardent pas la trace d'une première écriture (la
            // faute tient la carte en lecture), et ce recompte ne refuse
            // qu'une zone plus grande que toute la mémoire.
            let a_promettre = droits.ecriture && !z.droits.ecriture && !z.drapeaux.promise && !z.drapeaux.sans_reserve;
            if a_promettre && !engagement_possible(bout - ici) {
                return Err(Erreur::PlusDeMemoire);
            }
            self.zones.changer(ici, bout, |z| {
                z.droits = droits;
                z.drapeaux.promise |= a_promettre;
            }, &mut references)?;
            self.tables().proteger_plage(ici, bout, droits);
            ici = bout;
        }
        Ok(())
    }

    /// Retire les pages de [debut, fin[ sans toucher aux zones
    /// (MADV_DONTNEED) : elles se reliront à zéro, ou depuis le fichier
    /// projeté (les segments du programme compris). Les tables restent, la
    /// zone aussi. Mémoire tenue en LECTURE (6j, le `zap_page_range_single`
    /// de Linux sous `mmap_read_lock`), les tables sous leur verrou par
    /// tranches (espace_utilisateur.rs), interruptions actives : les fautes
    /// des autres fils continuent ; celles de la plage même peuvent poser
    /// une page juste avant ou juste après notre passage, ce que madvise
    /// permet (ses pages « peuvent » être rendues).
    pub fn oublier(&self, debut: u64, fin: u64) {
        for z in self.zones.morceaux(debut, fin) {
            EspaceUtilisateur::retirer_par_tranches(&self.espace, z.debut, z.fin, false, GRAND_LOT);
        }
    }

    /// Ses compteurs (voir le champ).
    pub fn compteurs(&self) -> &Arc<Compteurs> {
        &self.compteurs
    }

    /// Les processeurs qui ont chargé l'espace (espace_utilisateur.rs), à
    /// partager avec l'entrée du processus (processus.rs).
    pub fn processeurs(&mut self) -> crate::partage::Arc<espace_utilisateur::MasqueProcesseurs> {
        self.espace.get_mut().processeurs().clone()
    }

    /// La zone qui contient `adresse`, pour un message.
    pub fn zone_du_code(&self, adresse: u64) -> Option<ZoneDuCode> {
        let z = self.zones.trouver(adresse)?;
        // Le nom du fichier projeté, s'il y en a un (sous le verrou des
        // fichiers, pris sous la mémoire du processus).
        let nom = z.fichier.map_or(self.nom, |p| vfs::avec_systeme(|s, _| s.ouverts.fichier(Fichier::de(p.fichier)).nom));
        Some(ZoneDuCode { nom, nature: z.nature, fichier: z.fichier.is_some(), debut: z.debut, taille: z.taille() })
    }

    /// La taille de toutes ses zones, en octets (la « mémoire virtuelle »,
    /// le total-vm de Linux).
    pub fn taille_virtuelle(&self) -> u64 {
        self.zones.zones().iter().map(Zone::taille).sum()
    }

    /// Ses données au sens de RLIMIT_DATA : les zones privées
    /// inscriptibles qui ne sont pas la pile (`is_data_mapping` de Linux ;
    /// le `data_vm`, recompté ici d'après la carte).
    pub fn taille_donnees(&self) -> u64 {
        self.zones.zones().iter().filter(|z| est_des_donnees(z.droits, z.drapeaux)).map(Zone::taille).sum()
    }

    /// Les octets de [debut, fin[ déjà dans des zones : ce que MAP_FIXED
    /// remplacera (le `nr_pages` de `vms_gather_munmap_vmas`).
    pub fn deja_projete(&self, debut: u64, fin: u64) -> u64 {
        self.zones.morceaux(debut, fin).map(|z| z.taille()).sum()
    }
}
