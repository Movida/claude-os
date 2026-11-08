//! Les programmes de l'archive de démarrage : la déballer, lancer ce que
//! dit /etc/demarrage, reconnaître le format de chaque programme, les
//! exécuter.
//!
//! Le chargeur a déposé à côté du noyau une archive cpio (voir
//! ../formats/src/cpio.rs) ; le noyau la déballe dans son système de
//! fichiers (vfs.rs), puis lit /etc/demarrage : une commande par ligne,
//! avec ses arguments et son environnement, lancées l'une après l'autre
//! (la syntaxe : ../formats/src/commande.rs). Sans `fork` ni `execve`
//! (6l), aucun programme ne peut en lancer un autre : le noyau joue le
//! rôle d'`init` en attendant. En 6l, un vrai /init, lancé par son chemin
//! comme sous Linux, lancera un shell, et ce fichier deviendra un script.
//!
//! Le format d'un programme se reconnaît à ses premiers octets, sa
//! « signature » (magic number) :
//!   - « \0asm » : un module WebAssembly, le format natif de l'OS ;
//!   - « \x7fELF » : un exécutable Linux.
//! C'est le principe des « binfmt » de Linux (fs/binfmt_elf.c,
//! fs/binfmt_script.c pour « #! », binfmt_misc pour le reste) : chaque
//! format est essayé tour à tour, et le premier qui reconnaît le fichier
//! s'en charge. Le nom du fichier (son extension) ne compte pas.

use crate::descripteurs::Descripteurs;
use crate::faillible::{self, VecFaillible};
use crate::memoire::Acces;
use crate::partage::Arc;
use crate::{appels_fichiers, chargeur_elf, demarrage, pages, pile, processus, tache, vfs, wasi};
use fichiers::Identite;
use alloc::vec::Vec;
use core::fmt;
use fichiers::montages::Objet;
use fichiers::tmpfs::Numero;

/// L'environnement des programmes : de quoi savoir où est le dossier
/// personnel (/home/utilisateur, à l'utilisateur 1000, voir archive.txt),
/// et quel terminal les affiche (la console : un terminal « linux », comme
/// la console de Linux). Une ligne de /etc/demarrage peut en remplacer une
/// variable, ou en ajouter (`NOM=valeur` en tête, comme le shell).
const ENVIRONNEMENT: &[&[u8]] = &[b"HOME=/home/utilisateur", b"TERM=linux"];

/// Le fichier des commandes à lancer, et sa taille maximale : une page
/// suffit à des dizaines de lignes ; 64 Kio laissent de la marge sans
/// laisser un fichier géant remplir le tas du noyau.
const DEMARRAGE: &[u8] = b"/etc/demarrage";
const DEMARRAGE_MAX: u64 = 64 << 10;

/// L'identité des programmes : l'utilisateur 1000 (pile.rs).
const IDENTITE: Identite = Identite { uid: pile::UTILISATEUR as u32, gid: pile::GROUPE as u32 };

/// Le nom d'un programme en cours, pour les messages : le nom de base de
/// son fichier, coupé à 15 octets, comme le `comm` de la task_struct de
/// Linux (TASK_COMM_LEN, 16 avec le zéro final). Une valeur, et pas une
/// tranche : le fichier peut être renommé ou effacé pendant que le
/// programme tourne.
#[derive(Clone, Copy)]
pub struct NomCourt {
    octets: [u8; 15],
    longueur: u8,
}

impl NomCourt {
    pub const VIDE: NomCourt = NomCourt { octets: [0; 15], longueur: 0 };

    pub fn de(nom: &[u8]) -> NomCourt {
        let mut n = NomCourt::VIDE;
        let longueur = nom.len().min(n.octets.len());
        n.octets[..longueur].copy_from_slice(&nom[..longueur]);
        n.longueur = longueur as u8;
        n
    }

    pub fn octets(&self) -> &[u8] {
        &self.octets[..self.longueur as usize]
    }
}

impl fmt::Display for NomCourt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Nom(self.octets()).fmt(f)
    }
}

/// Le nom d'une entrée, pour l'afficher : un nom de fichier peut contenir
/// n'importe quel octet, que la console afficherait de travers. On montre
/// l'ASCII imprimable tel quel, et « ? » pour le reste.
#[derive(Clone, Copy)]
pub struct Nom<'a>(pub &'a [u8]);

impl fmt::Display for Nom<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &o in self.0 {
            let c = if o.is_ascii_graphic() || o == b' ' { o as char } else { '?' };
            fmt::Write::write_char(f, c)?;
        }
        // Une largeur demandée ({:<24}) : des espaces après le nom (un
        // caractère affiché par octet).
        for _ in self.0.len()..f.width().unwrap_or(0) {
            fmt::Write::write_char(f, ' ')?;
        }
        Ok(())
    }
}

/// Déballe l'archive de démarrage dans le système de fichiers de la racine
/// (vfs.rs), rend sa mémoire, puis lance les commandes de /etc/demarrage.
/// Une archive mal formée est refusée en entier, avant de rien déballer :
/// on ne lance pas la moitié d'un système.
pub fn demarrer() {
    // L'archive, telle que le chargeur l'a déposée, prêtée le temps du
    // déballage ; sa mémoire retourne ensuite à l'allocateur de pages.
    let ((valide, bilan), rendus) = demarrage::deballer_archive(|archive| {
        let mut valide = archive.is_some();
        match archive {
            None => afficherln!("[noyau] Pas d'archive de programmes."),
            Some((o, adresse)) => {
                afficherln!("[noyau] Archive de programmes : {} octets a {:#x}.", o.len(), adresse);
                if let Some(Err(e)) = formats::cpio::lire(o).find(Result::is_err) {
                    afficherln!("[noyau] Archive refusee : {}", e);
                    valide = false;
                }
            }
        }
        (valide, vfs::initialiser(archive.map(|(o, _)| o).filter(|_| valide)))
    });
    let bilan = match bilan {
        Ok(b) => b,
        Err(e) => return afficherln!("[noyau] Systeme de fichiers impossible a monter (errno {}).", e.errno()),
    };
    if valide {
        afficherln!("[noyau] Archive deballee : dossiers {}, fichiers {}, liens symboliques {}, liens physiques {}{} ; archive rendue ({} Kio).",
                    bilan.dossiers, bilan.fichiers, bilan.liens_symboliques, bilan.liens_physiques,
                    if bilan.refusees > 0 { " (des entrees refusees)" } else { "" }, rendus >> 10);
    }
    let texte = match lire_demarrage() {
        Ok(t) => t,
        // Linux, sans init, panique (« No working init found ») : ici, le
        // noyau le dit et continue (il n'a plus rien à faire, mais le
        // clavier marche encore).
        Err(e) => return afficherln!("[noyau] {} illisible (errno {}) : rien a lancer.", Nom(DEMARRAGE), e.errno()),
    };
    // Les lignes qui ont une commande (ou une erreur) : les autres sont
    // vides, ou des commentaires.
    let commandes = formats::commande::lignes(&texte)
        .filter(|(_, l)| tampon_pour(l).is_none_or(|mut t| !matches!(formats::commande::decouper(l, &mut t), Ok(None))))
        .count();
    afficherln!("[noyau] Lancement : {}, {} commandes.", Nom(DEMARRAGE), commandes);
    // Ce que le démarrage a fait des verrous, avant le premier programme
    // (make verrous).
    #[cfg(feature = "verrous")]
    crate::verrou::statistiques::afficher("Demarrage");
    let mut l = Lanceur::new(commandes);
    // Les lignes d'un groupe refusé, sautées jusqu'à celle-ci comprise.
    let mut sauter = 0;
    for (numero, ligne) in formats::commande::lignes(&texte) {
        if numero <= sauter {
            continue;
        }
        // La mémoire libre quand aucun programme ne tourne, avant tout ce
        // que la ligne fait prendre (voir `Lanceur`) ; dans un groupe, celle
        // de son début.
        if l.en_cours == 0 && l.groupe.is_none() {
            attendre_le_repos();
            l.libres = pages::libres();
            l.paralleles = false;
        }
        // Le tampon de la ligne et ce que `lancer` prend pour elle sont
        // rendus à la fin de ce bloc, avant de recueillir un programme.
        let action = {
            let Some(mut tampon) = tampon_pour(ligne) else {
                afficherln!("[noyau] {}, ligne {} : plus de memoire pour la lire", Nom(DEMARRAGE), numero);
                continue;
            };
            match formats::commande::decouper(ligne, &mut tampon) {
                Ok(None) => None,
                Ok(Some(formats::commande::Ligne::Attendre)) => Some(Action::Attendre),
                Ok(Some(formats::commande::Ligne::Dossier(chemin))) => {
                    l.changer_de_dossier(numero, chemin);
                    None
                }
                Ok(Some(formats::commande::Ligne::DebutDeGroupe)) => {
                    match verifier_groupe(&texte, numero) {
                        Ok(fin) => l.commencer_groupe(numero, fin),
                        Err((fin, raison)) => {
                            afficherln!("[noyau] {}, lignes {} a {} : groupe refuse : {}", Nom(DEMARRAGE), numero, fin, raison);
                            sauter = fin;
                        }
                    }
                    None
                }
                Ok(Some(formats::commande::Ligne::FinDeGroupe)) if l.groupe.is_some() => Some(Action::FinDeGroupe),
                Ok(Some(formats::commande::Ligne::FinDeGroupe)) => {
                    afficherln!("[noyau] {}, ligne {} : refusee : }} sans {{", Nom(DEMARRAGE), numero);
                    None
                }
                Ok(Some(formats::commande::Ligne::Commande(commande))) => {
                    let fond = commande.arriere_plan();
                    lancer(&mut l, numero, &commande).map(|t| if fond { Action::Fond(t) } else { Action::Premier(t) })
                }
                Err(e) => {
                    afficherln!("[noyau] {}, ligne {} : refusee : {}", Nom(DEMARRAGE), numero, e);
                    None
                }
            }
        };
        // Ce que la ligne a différé, comme à la sortie d'un appel système
        // (`reseau::socket::fermer_les_differees`) : le SIGIO des instances
        // d'inotify en O_ASYNC où elle a posé des événements (l'ouverture
        // d'un programme, d'une redirection), avant d'attendre le
        // programme ; les fichiers qu'a fermés un lancement refusé. Sans
        // cela, une instance restait chaînée au lanceur : plus aucun SIGIO
        // pour elle, et jamais rendue.
        crate::reseau::socket::fermer_les_differees();
        match action {
            None => {}
            Some(Action::Premier(t)) => l.attendre(t),
            // La place est réservée pour chaque commande du fichier ; si le
            // tas n'avait pas pu la donner, le programme est attendu tout de
            // suite, comme au premier plan.
            Some(Action::Fond(t)) => {
                if let Err(t) = l.fond.ajouter_ou_rendre(t) {
                    l.attendre(t);
                }
            }
            Some(Action::Attendre) => l.attendre_tous(),
            Some(Action::FinDeGroupe) => l.finir_groupe(),
        }
        // Et ce qu'a différé le recueil d'un programme.
        crate::reseau::socket::fermer_les_differees();
    }
    // Comme init, qui recueille ses enfants : le noyau attend ceux qui
    // tournent encore.
    l.attendre_tous();
    crate::reseau::socket::fermer_les_differees();
    // La pile de 16 Kio a-t-elle encore de la marge ? Ce qu'elle a vu de pire, une fois tout
    // fait. Un quart de réserve, pour les chemins que ces programmes n'ont pas pris.
    let (profondeur, taille) = (tache::plus_grande_profondeur(), crate::vmalloc::TAILLE_PILE as usize);
    let marge = if profondeur <= taille / 4 * 3 { "ok" } else { "ECHEC" };
    afficherln!("[noyau] Piles du noyau : {} octets au plus, sur {}, il reste de la marge : {}.", profondeur, taille, marge);
}

/// Lâche un dossier tenu par le lanceur (un inode du tmpfs).
fn lacher_dossier(o: Objet) {
    if let Some(n) = o.tmpfs() {
        vfs::avec(|fs, cadres| fs.lacher(n, cadres));
    }
}

impl Drop for Lanceur {
    fn drop(&mut self) {
        lacher_dossier(self.dossier);
    }
}

/// Ce que fait une ligne.
enum Action {
    /// Un programme lancé, à attendre tout de suite.
    Premier(Tache),
    /// Un programme lancé par `&`, à attendre au prochain `wait`.
    Fond(Tache),
    /// `wait`.
    Attendre,
    /// `}` : la fin d'un groupe.
    FinDeGroupe,
}

/// Un groupe de /etc/demarrage (6i) : ses lignes, et la mémoire libre à son
/// début, si rien ne tournait (sinon, rien n'est mesuré pour lui).
struct Groupe {
    debut: usize,
    fin: usize,
    mesure: bool,
}

/// Lit le groupe qui commence à la ligne `debut` de `texte` jusqu'à son `}`,
/// avant d'en lancer une ligne, comme sh : rend la ligne du `}`, ou, s'il
/// est refusé, la dernière ligne lue et pourquoi. Refusé, comme par sh, s'il
/// est vide ou sans `}`, ou si l'une de ses lignes l'est ; et, ce que sh
/// permet mais que nous ne savons pas mesurer, un groupe dans un groupe, ou
/// un programme lancé par `&` sans `wait` avant le `}` (sh ne l'attend pas :
/// il tournerait encore quand on mesure la mémoire rendue du groupe).
fn verifier_groupe(texte: &[u8], debut: usize) -> Result<usize, (usize, Refus)> {
    use formats::commande::Ligne;
    let (mut commandes, mut en_fond) = (0, false);
    // La première raison de le refuser ; on lit quand même jusqu'à son `}`,
    // pour sauter tout le groupe (les groupes qu'il contient compris).
    let mut refus = None;
    let mut profondeur = 0;
    let mut derniere = debut;
    for (numero, ligne) in formats::commande::lignes(texte).skip(debut) {
        derniere = numero;
        let Some(mut tampon) = tampon_pour(ligne) else {
            // Plus de mémoire pour découper la ligne : le groupe est refusé,
            // mais lu jusqu'à son `}` (ses accolades se voient sans tampon),
            // pour le sauter en entier.
            refus.get_or_insert(Refus::Memoire);
            match formats::commande::accolade(ligne) {
                Some(true) => profondeur += 1,
                Some(false) if profondeur > 0 => profondeur -= 1,
                Some(false) => return Err((numero, refus.take().unwrap_or(Refus::Memoire))),
                None => {}
            }
            continue;
        };
        match formats::commande::decouper(ligne, &mut tampon) {
            Ok(None) => {}
            // `cd` et `wait` sont des commandes pour sh : un groupe qui n'a
            // qu'elles n'est pas vide.
            Ok(Some(Ligne::Dossier(_))) => commandes += 1,
            Ok(Some(Ligne::Commande(c))) => {
                commandes += 1;
                en_fond |= c.arriere_plan();
            }
            Ok(Some(Ligne::Attendre)) => {
                commandes += 1;
                en_fond = false;
            }
            Ok(Some(Ligne::DebutDeGroupe)) => {
                profondeur += 1;
                refus.get_or_insert(Refus::Imbrique(numero));
            }
            Ok(Some(Ligne::FinDeGroupe)) if profondeur > 0 => profondeur -= 1,
            Ok(Some(Ligne::FinDeGroupe)) => {
                return match refus {
                    Some(r) => Err((numero, r)),
                    None if commandes == 0 => Err((numero, Refus::Vide)),
                    None if en_fond => Err((numero, Refus::SansWait)),
                    None => Ok(numero),
                };
            }
            Err(e) => {
                refus.get_or_insert(Refus::Ligne(numero, e));
            }
        }
    }
    Err((derniere, Refus::SansFin))
}

/// Pourquoi un groupe est refusé (sans accents : affiché).
enum Refus {
    Memoire,
    Vide,
    SansFin,
    SansWait,
    Imbrique(usize),
    Ligne(usize, formats::commande::Erreur),
}

impl fmt::Display for Refus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Refus::Memoire => f.write_str("plus de memoire pour le lire"),
            Refus::Vide => f.write_str("vide"),
            Refus::SansFin => f.write_str("pas de } avant la fin du fichier"),
            Refus::SansWait => f.write_str("un programme lance par & sans wait avant }"),
            Refus::Imbrique(n) => write!(f, "un groupe dans le groupe, ligne {}", n),
            Refus::Ligne(n, e) => write!(f, "ligne {} : {}", n, e),
        }
    }
}

/// Un programme lancé, que le lanceur recueillera.
enum Tache {
    /// Un programme Linux : son processus (fini quand son dernier fil l'est,
    /// pas forcément le principal), son nom, son fichier (tenu, et protégé
    /// contre l'écriture tant qu'il s'exécute).
    Linux { processus: Arc<processus::Entree>, nom: NomCourt, fichier: Numero },
    /// Un programme WebAssembly : sa tâche du noyau (elle dit elle-même
    /// comment il s'est terminé).
    Wasm(Arc<tache::Tache>),
}

/// Le lanceur (le rôle d'init) : les programmes lancés par `&` et pas
/// encore recueillis, combien de programmes tournent, et la mémoire libre
/// quand le premier d'entre eux a été lancé. « Memoire rendue » compare la
/// mémoire libre quand aucun programme ne tourne : avant le premier, et
/// une fois le dernier recueilli. Un programme qui a tourné seul le dit
/// pour lui ; ceux qui ont tourné ensemble, ensemble, au `wait` qui les
/// recueille (avec deux programmes à la fois, la mémoire libre ne dit plus
/// rien d'un seul).
struct Lanceur {
    fond: Vec<Tache>,
    en_cours: usize,
    libres: usize,
    /// Un programme a été lancé pendant qu'un autre tournait.
    paralleles: bool,
    /// Son dossier courant (6i) : la racine, puis celui du dernier `cd`,
    /// tenu ; celui de chaque programme lancé, et le départ d'une
    /// redirection par un chemin relatif. Le chemin qu'en donne `cd`, en
    /// forme simple, pour PWD ; le précédent, pour OLDPWD (vide avant le
    /// premier `cd`), comme dash.
    dossier: Objet,
    pwd: Vec<u8>,
    oldpwd: Vec<u8>,
    /// Le groupe en cours (6i) : ses programmes ne disent pas leur mémoire
    /// rendue, le groupe la dit à son `}`.
    groupe: Option<Groupe>,
}

impl Lanceur {
    /// La liste des programmes en arrière-plan a la place d'une entrée par
    /// commande du fichier (`commandes`) : elle ne grandit pas pendant
    /// qu'ils tournent.
    fn new(commandes: usize) -> Lanceur {
        let mut fond = Vec::new();
        // Sans cette place, chaque programme lancé en fond retentera (voir
        // `demarrer`).
        let _ = fond.try_reserve_exact(commandes);
        let dossier = vfs::avec_systeme(|s, _| {
            let r = s.racine();
            if let Some(n) = r.tmpfs() {
                s.fs.prendre(n);
            }
            r
        });
        Lanceur { fond, en_cours: 0, libres: 0, paralleles: false, dossier, pwd: copie(b"/"), oldpwd: Vec::new(), groupe: None }
    }

    /// `{` d'un groupe vérifié, qui finit à la ligne `fin` : la mémoire
    /// libre maintenant, si rien ne tourne.
    fn commencer_groupe(&mut self, debut: usize, fin: usize) {
        let mesure = self.en_cours == 0;
        if mesure {
            attendre_le_repos();
            self.libres = pages::libres();
            self.paralleles = false;
        }
        self.groupe = Some(Groupe { debut, fin, mesure });
    }

    /// `}` : tous ses programmes sont recueillis (ceux lancés par `&` l'ont
    /// été par un `wait`, `verifier_groupe` l'exige) ; sa mémoire rendue,
    /// s'il a été mesuré.
    fn finir_groupe(&mut self) {
        let Some(g) = self.groupe.take() else { return };
        if g.mesure && self.en_cours == 0 {
            attendre_le_repos();
            afficherln!("[noyau] Groupe des lignes {} a {} : memoire rendue : {}.", g.debut, g.fin,
                        Rendue(self.libres, pages::libres(), crate::signaux::en_file(), crate::reseau::paquet::vivants()));
        } else {
            afficherln!("[noyau] Groupe des lignes {} a {} : termine (des programmes tournaient deja : pas de mesure).", g.debut, g.fin);
        }
    }

    /// `cd CHEMIN` (absolu, en forme simple) : le dossier courant des lignes
    /// suivantes. Un dossier introuvable, ou qui n'en est pas un : rien ne
    /// change, et les lignes suivantes tournent dans l'ancien (le « can't
    /// cd » de dash).
    fn changer_de_dossier(&mut self, numero: usize, chemin: &[u8]) {
        let nouveau = match appels_fichiers::dossier_pour_le_lanceur(chemin) {
            Ok(o) => o,
            Err(e) => return afficherln!("[noyau] {}, ligne {} : cd {} impossible (errno {})", Nom(DEMARRAGE), numero, Nom(chemin), e.errno()),
        };
        let Ok(pwd) = faillible::copie(chemin) else {
            lacher_dossier(nouveau);
            return afficherln!("[noyau] {}, ligne {} : cd : plus de memoire", Nom(DEMARRAGE), numero);
        };
        lacher_dossier(core::mem::replace(&mut self.dossier, nouveau));
        self.oldpwd = core::mem::replace(&mut self.pwd, pwd);
    }

    /// Un programme va être lancé.
    fn commencer(&mut self) {
        if self.en_cours > 0 {
            self.paralleles = true;
        }
        self.en_cours += 1;
    }

    /// Attend la fin du programme `t`, au premier plan. En attendant, comme
    /// un init, recueille aussitôt chaque programme lancé par `&` qui se
    /// termine : un zombie ne reste pas en attendant le prochain `wait`.
    fn attendre(&mut self, t: Tache) {
        loop {
            self.recueillir_les_morts();
            if t.fini() {
                return self.recueillir(t);
            }
            let fond = &self.fond;
            tache::dormir_tant_que(|| !t.fini() && !fond.iter().any(Tache::fini));
        }
    }

    /// Recueille les programmes lancés par `&` qui se sont terminés.
    fn recueillir_les_morts(&mut self) {
        while let Some(i) = self.fond.iter().position(Tache::fini) {
            let t = self.fond.remove(i);
            self.recueillir(t);
        }
    }

    /// Recueille le programme `t`, qui se termine (ou s'est terminé), et le
    /// dit.
    fn recueillir(&mut self, t: Tache) {
        // Pour les statistiques des verrous (make verrous) : le nom du
        // programme.
        #[cfg(feature = "verrous")]
        let nom_du_programme = match &t {
            Tache::Linux { nom, .. } => *nom,
            Tache::Wasm(tache) => tache.nom(),
        };
        let fin = match t {
            Tache::Linux { processus: p, nom, fichier } => {
                tache::dormir_tant_que(|| !p.est_zombie());
                let pid = p.pid();
                drop(p);
                let code = processus::recueillir(pid).unwrap_or(-1);
                vfs::avec(|fs, cadres| {
                    fs.permettre_ecriture(fichier);
                    fs.lacher(fichier, cadres);
                });
                Some((nom, code))
            }
            Tache::Wasm(tache) => {
                tache::attendre(&tache);
                None
            }
        };
        self.en_cours -= 1;
        if self.en_cours == 0 {
            attendre_le_repos();
        }
        let rendue = || Rendue(self.libres, pages::libres(), crate::signaux::en_file(), crate::reseau::paquet::vivants());
        let groupe = self.groupe.is_some();
        match fin {
            Some((nom, code)) if self.en_cours == 0 && !self.paralleles && !groupe => {
                afficherln!("[noyau] {} : termine, code de sortie {} ; memoire rendue : {}.", nom, code, rendue())
            }
            Some((nom, code)) => afficherln!("[noyau] {} : termine, code de sortie {}.", nom, code),
            None => {}
        }
        if self.en_cours == 0 && self.paralleles && !groupe {
            afficherln!("[noyau] Programmes en parallele : memoire rendue : {}.", rendue());
        }
        // Ce que les verrous ont fait pendant ce programme (et ceux qui
        // tournaient avec lui), depuis l'affichage précédent.
        #[cfg(feature = "verrous")]
        crate::verrou::statistiques::afficher(nom_du_programme);
    }

    /// `wait` : recueille tous les programmes lancés par `&`, à mesure
    /// qu'ils se terminent.
    fn attendre_tous(&mut self) {
        while !self.fond.is_empty() {
            self.recueillir_les_morts();
            let fond = &self.fond;
            tache::dormir_tant_que(|| !fond.is_empty() && !fond.iter().any(Tache::fini));
        }
    }
}

/// Ce que dit « memoire rendue » : ok, ou ECHEC avec l'écart, en pages
/// (libres avant le premier programme, puis maintenant), pour chercher ce
/// qui manque (ou ce qui a été rendu en retard, d'un programme d'avant).
/// Depuis 6f, aussi le compte des siginfo en file de l'utilisateur
/// (signaux.rs) : sans programme, il doit être revenu à 0, sinon un compte
/// perdu finirait par refuser des signaux (RLIMIT_SIGPENDING). Depuis 6g,
/// un ECHEC dit aussi les octets des paquets du réseau encore vivants
/// (reseau::paquet) : un écart qui vient d'une file du réseau se voit tout
/// de suite.
struct Rendue(usize, usize, u64, usize);

impl fmt::Display for Rendue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match (self.1 as i64 - self.0 as i64, self.2) {
            (0, 0) => write!(f, "ok"),
            (0, n) => write!(f, "ECHEC ({} siginfo encore comptes en file)", n),
            (d, _) => write!(f, "ECHEC ({:+} pages libres, {} octets de paquets vivants)", d, self.3),
        }
    }
}

/// Attend le repos avant de mesurer la mémoire (celle d'avant un programme,
/// celle d'après) : le rendeur a rendu les piles de toutes les tâches
/// mortes (tache.rs), le cache des piles est vidé (vmalloc.rs : ses cadres
/// ne sont pas libres), et le réseau est au repos (reseau::au_repos), 4 s
/// au plus : un programme qui a écrit à une machine muette juste avant de
/// finir a laissé son paquet dans la file du voisin, jusqu'à l'échec de
/// celui-ci (3 s, inet::voisins). Par tranches d'une milliseconde (le tic).
fn attendre_le_repos() {
    tache::attendre_le_rendeur();
    crate::vmalloc::vider_le_cache_des_piles();
    let fin = crate::temps::ns_monotone() + 4_000_000_000;
    while !crate::reseau::au_repos() && crate::temps::ns_monotone() < fin {
        let interruptions = crate::cpu::couper_interruptions();
        tache::courante().preparer_sommeil(crate::attente::Sommeil::Ininterruptible);
        crate::attente::dormir(Some(crate::temps::ns_monotone() + 1_000_000), crate::attente::Sommeil::Ininterruptible);
        tache::courante().reveille();
        if interruptions {
            crate::cpu::activer_interruptions();
        }
    }
}

impl Tache {
    /// Le programme est-il fini (le processus, zombie ; la tâche du
    /// programme WebAssembly, morte) ?
    fn fini(&self) -> bool {
        match self {
            Tache::Linux { processus, .. } => processus.est_zombie(),
            Tache::Wasm(t) => t.est_morte(),
        }
    }
}

/// Le tampon où découper `ligne` (formats::commande), s'il y a la place.
fn tampon_pour(ligne: &[u8]) -> Option<Vec<u8>> {
    faillible::remplie(formats::commande::taille_tampon(ligne), 0).ok()
}

/// Le contenu de /etc/demarrage, lu en root (comme `init` lit son
/// `inittab`), dans un bloc du tas.
fn lire_demarrage() -> Result<Vec<u8>, fichiers::Erreur> {
    let (n, _, _trouve) = appels_fichiers::trouver_pour(Identite::ROOT, DEMARRAGE)?;
    let (mode, taille) = vfs::avec(|fs, _| {
        let a = fs.attributs(n);
        (a.mode, a.taille)
    });
    // Un fichier ordinaire seulement : vfs::lire ne sait lire que lui.
    let lu = if mode & fichiers::S_IFMT == fichiers::S_IFDIR {
        Err(fichiers::Erreur::EISDIR)
    } else if mode & fichiers::S_IFMT != fichiers::S_IFREG {
        Err(fichiers::Erreur::EINVAL)
    } else if taille > DEMARRAGE_MAX {
        Err(fichiers::Erreur::EFBIG)
    } else {
        faillible::remplie(taille as usize, 0).map_err(fichiers::Erreur::from).map(|mut texte| {
            let lus = vfs::lire(n, 0, &mut texte);
            texte.truncate(lus);
            texte
        })
    };
    vfs::avec(|fs, cadres| fs.lacher(n, cadres));
    lu
}

/// Lance la commande de la ligne `numero` : son environnement (celui du
/// noyau, remplacé ou complété par ses affectations), son programme
/// (résolu comme `execve`, sans `PATH`, avec les droits de l'utilisateur
/// 1000), ses arguments.
fn lancer(l: &mut Lanceur, numero: usize, commande: &formats::commande::Commande) -> Option<Tache> {
    let programme = commande.programme();
    let refus = |raison: &dyn fmt::Display| {
        afficherln!("[noyau] {}, ligne {} : refusee : {}", Nom(DEMARRAGE), numero, raison);
        None
    };
    let (mut environnement, mut arguments, mut dossiers, mut ecoutes) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut entrees = Entrees(Vec::new());
    // L'environnement du noyau, PWD et OLDPWD, puis les affectations.
    let place = ENVIRONNEMENT.len() + 2 + commande.affectations().count();
    if environnement.try_reserve_exact(place).is_err()
        || arguments.try_reserve_exact(commande.arguments().count()).is_err()
        || dossiers.try_reserve_exact(commande.dossiers().count()).is_err()
        || ecoutes.try_reserve_exact(commande.ecoutes().count()).is_err()
        || entrees.0.try_reserve_exact(commande.redirections().count()).is_err()
    {
        return refus(&"plus de memoire");
    }
    // Les redirections d'abord, de gauche à droite, comme sh (avant même de
    // chercher le programme) : chaque fichier ouvert en lecture, avec les
    // droits du noyau (un init, un shell de root, ou systemd, qui ouvre
    // StandardInput=file: avant de changer d'utilisateur : un programme
    // peut ainsi recevoir un fichier qu'il ne pourrait pas ouvrir). Un
    // fichier qui ne s'ouvre pas : la commande n'est pas lancée, et
    // les lignes suivantes, si (« cannot open » de dash). Les fichiers
    // ouverts sont lâchés en sortant (`Entrees`), le programme tenant les
    // siens.
    for (fd, chemin) in commande.redirections() {
        match appels_fichiers::ouvrir_pour_le_lanceur(l.dossier, chemin) {
            Ok(f) => entrees.0.ajouter_dans_la_place((fd, f)),
            Err(e) => return refus(&format_args!("{} : impossible a ouvrir (errno {})", Nom(chemin), e.errno())),
        }
    }
    // PWD (et OLDPWD après un `cd`), comme dash les donne aux commandes
    // qu'il lance (même sans `cd` : PWD=/).
    let (Ok(pwd), Ok(oldpwd)) = (faillible::concatenation(&[b"PWD=", &l.pwd]), faillible::concatenation(&[b"OLDPWD=", &l.oldpwd]))
    else {
        return refus(&"plus de memoire");
    };
    // Dans la place réservée juste au-dessus : plus rien n'échoue.
    for &v in ENVIRONNEMENT {
        environnement.ajouter_dans_la_place(v);
    }
    environnement.ajouter_dans_la_place(&pwd);
    if !l.oldpwd.is_empty() {
        environnement.ajouter_dans_la_place(&oldpwd);
    }
    for affectation in commande.affectations() {
        // « NOM=... » remplace la variable NOM du noyau, comme le shell.
        let nom = &affectation[..=affectation.iter().position(|&o| o == b'=').unwrap_or(0)];
        match environnement.iter().position(|v| v.starts_with(nom)) {
            Some(i) => environnement[i] = affectation,
            None => environnement.ajouter_dans_la_place(affectation),
        }
    }
    commande.arguments().for_each(|a| arguments.ajouter_dans_la_place(a));
    commande.dossiers().for_each(|d| dossiers.ajouter_dans_la_place(d));
    commande.ecoutes().for_each(|e| ecoutes.ajouter_dans_la_place(e));
    let (n, complet, trouve) = match appels_fichiers::trouver_pour(IDENTITE, programme) {
        Ok(n) => n,
        Err(e) => return refus(&format_args!("{} : introuvable (errno {})", Nom(programme), e.errno())),
    };
    let lancement = Lancement {
        chemin: programme,
        complet: &complet,
        trouve: &trouve,
        arguments: &arguments,
        environnement: &environnement,
        dossiers: &dossiers,
        ecoutes: &ecoutes,
        entrees: &entrees.0,
        dossier: l.dossier,
        fond: commande.arriere_plan(),
    };
    let t = executer(l, numero, n, &lancement);
    // Un programme Linux lancé garde son fichier jusqu'à ce qu'on le
    // recueille ; sinon, on le lâche ici.
    if !matches!(t, Some(Tache::Linux { .. })) {
        vfs::avec(|fs, cadres| fs.lacher(n, cadres));
    }
    t
}

/// Les fichiers ouverts pour les redirections d'une ligne (`N< chemin`) :
/// le descripteur, le fichier ouvert. Lâchés quand la ligne est lancée (ou
/// refusée) : un programme lancé tient ceux qu'il a reçus.
struct Entrees(Vec<(u8, crate::descripteurs::Fichier)>);

impl Drop for Entrees {
    fn drop(&mut self) {
        vfs::avec_systeme(|s, cadres| {
            for &(_, f) in &self.0 {
                s.lacher(f, cadres);
            }
        });
    }
}

/// Une copie de `octets` dans un bloc du tas, vide s'il n'y a pas la place
/// (pour un chemin canonique, qui ne doit jamais faire échouer un
/// lancement).
fn copie(octets: &[u8]) -> Vec<u8> {
    faillible::copie(octets).unwrap_or_default()
}

/// Ce qu'une ligne de /etc/demarrage donne au programme.
struct Lancement<'a> {
    /// Son chemin (AT_EXECFN), tel qu'écrit.
    chemin: &'a [u8],
    /// Son chemin canonique (liens résolus), vide s'il n'a pas pu être
    /// calculé : celui de son fichier ouvert (FichierOuvert::chemin).
    complet: &'a [u8],
    /// Son chemin, tenu depuis qu'on l'a trouvé : le lieu de son fichier
    /// ouvert (inotify, 6i).
    trouve: &'a appels_fichiers::CheminTenu,
    /// argv : le chemin, puis les arguments.
    arguments: &'a [&'a [u8]],
    /// envp : des « NOM=valeur ».
    environnement: &'a [&'a [u8]],
    /// Les dossiers pré-ouverts d'un programme WebAssembly.
    dossiers: &'a [&'a [u8]],
    /// Ses écoutes TCP pré-ouvertes (6h) : l'adresse, le port, et le mot
    /// `--tcplisten=` tel qu'écrit (pour les messages).
    ecoutes: &'a [([u8; 4], u16, &'a [u8])],
    /// Ses redirections (6i), ouvertes, dans l'ordre de la ligne : le
    /// descripteur, le fichier ouvert (que tient encore la ligne).
    entrees: &'a [(u8, crate::descripteurs::Fichier)],
    /// Son dossier courant : celui du lanceur (tenu par lui).
    dossier: Objet,
    /// Lancé par `&` : son entrée standard est /dev/null, comme sous `sh`
    /// (sauf redirection).
    fond: bool,
}

/// Exécute le programme du fichier `n`, d'après sa signature.
fn executer(l: &mut Lanceur, numero: usize, n: Numero, lancement: &Lancement) -> Option<Tache> {
    let chemin = lancement.chemin;
    let nom = NomCourt::de(chemin.rsplit(|&o| o == b'/').next().unwrap_or(chemin));
    // Le droit de l'exécuter d'abord, quel que soit son format : un fichier
    // ordinaire, avec le bit x pour l'utilisateur 1000 (EACCES sinon, pour
    // un dossier ou un périphérique aussi, comme do_open_execat). Avant de
    // rien lire : vfs::lire ne sait lire qu'un fichier ordinaire.
    if let Err(e) = vfs::avec(|fs, _| fs.peut_executer(IDENTITE, n)) {
        afficherln!("[noyau] {} : pas le droit de l'executer (errno {})", nom, e.errno());
        return None;
    }
    let mut signature = [0u8; 4];
    let lus = vfs::lire(n, 0, &mut signature);
    match &signature[..lus] {
        // WASI a ses propres descripteurs (les dossiers pré-ouverts, à
        // partir de 3) : une redirection n'y a pas encore de sens.
        [0, b'a', b's', b'm'] if !lancement.entrees.is_empty() => {
            afficherln!("[noyau] {}, ligne {} : refusee : une redirection pour un programme WebAssembly", Nom(DEMARRAGE), numero);
            None
        }
        [0, b'a', b's', b'm'] => executer_wasm(l, nom, n, lancement),
        // Les dossiers pré-ouverts sont une affaire de WebAssembly : un
        // programme Linux voit tout l'arbre, avec ses droits. Les écoutes
        // aussi : un programme Linux crée les siennes.
        [0x7f, b'E', b'L', b'F'] if !lancement.dossiers.is_empty() => {
            afficherln!("[noyau] {}, ligne {} : refusee : --dir= pour un programme Linux", Nom(DEMARRAGE), numero);
            None
        }
        [0x7f, b'E', b'L', b'F'] if !lancement.ecoutes.is_empty() => {
            afficherln!("[noyau] {}, ligne {} : refusee : --tcplisten= pour un programme Linux", Nom(DEMARRAGE), numero);
            None
        }
        _ => {
            // Comme l'`execve` de Linux : le fichier ouvert (`do_open_execat` :
            // IN_OPEN), protégé contre l'écriture (ETXTBSY : refermé aussitôt,
            // IN_CLOSE_NOWRITE, sans rien lire), puis lu (`prepare_binprm` :
            // IN_ACCESS s'il n'est pas vide), avant de savoir s'il est
            // exécutable (un format inconnu : ENOEXEC, refermé ; mesuré).
            let fichier = match appels_fichiers::ouvrir_inode(n, chemin, copie(lancement.complet), crate::descripteurs::Sorte::Fichier,
                                                             lancement.trouve) {
                Ok(f) => f,
                Err(e) => {
                    afficherln!("[noyau] {} : ouverture impossible (errno {})", nom, e.errno());
                    return None;
                }
            };
            let lacher = || vfs::avec_systeme(|s, cadres| s.lacher(fichier, cadres));
            let Some(protection) = Protection::prendre(n) else {
                lacher();
                afficherln!("[noyau] {} : ouvert en ecriture, ne peut pas etre execute (ETXTBSY)", nom);
                return None;
            };
            if lus > 0 {
                appels_fichiers::annoncer_la_lecture(fichier);
            }
            if signature[..lus] == [0x7f, b'E', b'L', b'F'] {
                return executer_elf(l, nom, n, lancement, fichier, protection);
            }
            drop(protection);
            lacher();
            afficherln!("[noyau] {} : format inconnu, ignore.", nom);
            None
        }
    }
}

/// La protection d'un programme contre l'écriture (ETXTBSY : ses pages
/// seront bientôt celles du programme), prise à son ouverture
/// (`exe_file_deny_write_access`, dans le `do_open_execat` de Linux) :
/// rendue si son lancement est refusé ensuite ; gardée par le lanceur s'il
/// est lancé, jusqu'à son recueil (`Lanceur::recueillir`).
struct Protection(Numero);

impl Protection {
    /// None : le fichier est ouvert en écriture.
    fn prendre(n: Numero) -> Option<Protection> {
        vfs::avec(|fs, _| fs.refuser_ecriture(n)).ok().map(|()| Protection(n))
    }

    /// Le programme est lancé : la protection reste, jusqu'à son recueil.
    fn garder(self) {
        core::mem::forget(self);
    }
}

impl Drop for Protection {
    fn drop(&mut self) {
        vfs::avec(|fs, _| fs.permettre_ecriture(self.0));
    }
}

/// Un programme Linux : on vérifie le fichier, on le charge dans un espace
/// d'adressage neuf, puis on l'exécute, dans l'anneau 3, jusqu'à ce qu'il se
/// termine. Son espace est alors détruit, et doit rendre toute sa mémoire.
///
/// `fichier` : le programme ouvert (que tiendront ses zones), lâché ici ;
/// `protection` : sa protection contre l'écriture, que garde le lanceur
/// s'il est lancé (rendue sinon, avec elle).
fn executer_elf(l: &mut Lanceur, nom: NomCourt, n: Numero, lancement: &Lancement, fichier: crate::descripteurs::Fichier,
                protection: Protection) -> Option<Tache> {
    let lacher_le_programme = || vfs::avec_systeme(|s, cadres| s.lacher(fichier, cadres));
    // Un refus : le dire, et rien n'est lancé ; avant le chargement, le
    // fichier du programme encore ouvert est lâché (IN_CLOSE_NOWRITE).
    macro_rules! refus {
        ($($t:tt)*) => {{
            afficherln!($($t)*);
            return None;
        }};
    }
    macro_rules! refus_ouvert {
        ($($t:tt)*) => {{
            lacher_le_programme();
            refus!($($t)*)
        }};
    }
    let chemin = lancement.chemin;
    // Le fichier, lu par morceaux : la bibliothèque des formats ne voit que
    // des copies (chargeur_elf::verifier).
    let lire = |position: u64, tampon: &mut [u8]| vfs::lire(n, position, tampon) == tampon.len();
    let taille = vfs::avec(|fs, _| fs.attributs(n).taille);
    let (entete, table) = match chargeur_elf::verifier(taille, lire) {
        Ok(v) => v,
        Err(e) => refus_ouvert!("[noyau] {} : programme Linux refuse : {}", nom, e),
    };
    let executable = match formats::elf::lire_entetes(&entete, &table, taille) {
        Ok(x) => x,
        Err(e) => refus_ouvert!("[noyau] {} : programme Linux refuse : {}", nom, e),
    };
    // Un programme dynamique : le chemin de son interpréteur, lu dans le
    // fichier (hors de la table des en-têtes), dans un bloc du tas (4 Kio
    // au plus : la pile du noyau ne fait que 16 Kio).
    let mut chemin_interpreteur = Vec::new();
    if let Some((position, longueur)) = executable.interpreteur() {
        if chemin_interpreteur.redimensionner(longueur, 0).is_err() {
            refus_ouvert!("[noyau] {} : plus de memoire pour le chemin de l'interpreteur", nom);
        }
        if !lire(position, &mut chemin_interpreteur) {
            refus_ouvert!("[noyau] {} : programme Linux refuse : {}", nom, formats::elf::Erreur::InterpreteurHorsDuFichier);
        }
        match formats::elf::chemin_interpreteur(&chemin_interpreteur) {
            Ok(c) => {
                let longueur = c.len();
                chemin_interpreteur.truncate(longueur);
            }
            Err(e) => refus_ouvert!("[noyau] {} : programme Linux refuse : {}", nom, e),
        }
    }
    let identite = IDENTITE;
    // L'interpréteur, après le programme, comme l'ouvre `load_elf_binary`
    // (inotify voit le programme d'abord, mesuré : IN_OPEN et IN_ACCESS du
    // programme, puis ceux de ld-linux ; et, s'il manque, la fermeture du
    // programme après la sienne) : trouvé, vérifié, son fichier ouvert (voir
    // `ouvrir_interpreteur`). Il reste protégé contre l'écriture jusqu'à la
    // fin du chargement, comme chez Linux.
    let interpreteur = match executable.interpreteur() {
        None => None,
        Some(_) => match ouvrir_interpreteur(&chemin_interpreteur) {
            Ok(i) => Some(i),
            Err(e) => refus_ouvert!("[noyau] {} : interpreteur {} : {} (errno {})", nom, Nom(&chemin_interpreteur), e, e.errno()),
        },
    };
    let executable_interpreteur = match &interpreteur {
        None => None,
        Some(i) => match formats::elf::lire_entetes(&i.entete, &i.table, i.taille) {
            Ok(x) => Some((x, i.fichier)),
            Err(e) => {
                let e = EchecInterpreteur::Format(chargeur_elf::Refus::Format(e));
                fermer_interpreteur(interpreteur.as_ref());
                refus_ouvert!("[noyau] {} : interpreteur {} : {} (errno {})", nom, Nom(&chemin_interpreteur), e, e.errno());
            }
        },
    };
    let charge = chargeur_elf::charger(&executable, nom, fichier, executable_interpreteur.as_ref().map(|(x, f)| (x, *f)));
    lacher_le_programme();
    let (mut programme, images) = match charge {
        Ok(p) => p,
        Err(e) => {
            fermer_interpreteur(interpreteur.as_ref());
            match e {
                chargeur_elf::Refus::Format(e) => refus!("[noyau] {} : programme Linux refuse : {}", nom, e),
                chargeur_elf::Refus::Chevauchement => {
                    refus!("[noyau] {} : interpreteur {} : refuse : {}", nom, Nom(&chemin_interpreteur), e)
                }
                e => refus!("[noyau] {} : chargement impossible : {}", nom, e),
            }
        }
    };
    let image = images.programme;
    let (debut, fin) = image.etendue();
    let genre = match executable.genre() {
        formats::elf::Genre::Fixe => "ET_EXEC",
        formats::elf::Genre::Relogeable => "ET_DYN",
    };
    afficherln!("[noyau] {} : programme Linux (ELF {}), {} octets, point d'entree {:#x}, segments :",
                nom, genre, taille, image.entree());
    for s in image.segments() {
        afficherln!("        {:#010x}-{:#010x} {}{}{} ({} octets du fichier)",
                    s.adresse, s.adresse + s.taille, 'r',
                    if s.ecriture { 'w' } else { '-' }, if s.execution { 'x' } else { '-' }, s.taille_fichier);
    }
    // Un ET_DYN sans interpréteur, ou un interpréteur : la première
    // projection de l'espace, elle doit être tout en haut sous la base des
    // projections (à son alignement près). Un PIE : à ELF_ET_DYN_BASE.
    let base = crate::memoire::disposition().base_mmap;
    let en_haut = |fin: u64, alignement: u64| if fin <= base && base - fin < alignement { "ok" } else { "ECHEC" };
    match (executable.genre(), &images.interpreteur) {
        // Posé à l'adresse que suggérait son fichier (sa première adresse,
        // si elle n'est pas 0, et libre) : rien à vérifier de plus.
        (formats::elf::Genre::Relogeable, None) if executable.etendue().0 != 0 && debut == executable.etendue().0 => {
            afficherln!("        image a {:#x}-{:#x}, a l'adresse que suggere son fichier.", debut, fin)
        }
        (formats::elf::Genre::Relogeable, None) => {
            afficherln!("        image a {:#x}-{:#x}, tout en haut sous la base des projections : {}.",
                        debut, fin, en_haut(fin, executable.alignement()))
        }
        (formats::elf::Genre::Relogeable, Some(_)) => afficherln!("        image a {:#x}-{:#x} (ELF_ET_DYN_BASE).", debut, fin),
        (formats::elf::Genre::Fixe, _) => {}
    }
    if let Some(i) = &images.interpreteur {
        // Un ET_DYN posé sans suggestion (ld-linux : ses adresses partent
        // de 0) est tout en haut ; un ET_EXEC, à ses propres adresses.
        let (debut, fin) = i.etendue();
        let interpreteur = Nom(&chemin_interpreteur);
        if i.executable().genre() == formats::elf::Genre::Relogeable && debut != i.executable().etendue().0 {
            afficherln!("        interpreteur {} : image a {:#x}-{:#x}, tout en haut sous la base des projections : {}, point d'entree {:#x}.",
                        interpreteur, debut, fin, en_haut(fin, 4096), i.entree());
        } else {
            afficherln!("        interpreteur {} : image a {:#x}-{:#x}, a ses propres adresses, point d'entree {:#x}.",
                        interpreteur, debut, fin, i.entree());
        }
    }
    // Le code au point d'entrée, relu dans l'espace du programme, doit être
    // celui du fichier.
    // (16 octets au plus : ce qu'il reste du fichier après le point
    // d'entrée, dans son segment.)
    let mut attendu = [0u8; 16];
    let longueur = image
        .segments()
        .find_map(|s| {
            let decalage = programme.entree.checked_sub(s.adresse).filter(|&d| d < s.taille_fichier)?;
            let longueur = (s.taille_fichier - decalage).min(16) as usize;
            lire(s.position + decalage, &mut attendu[..longueur]).then_some(longueur)
        })
        .unwrap_or(0);
    // La page du point d'entrée vient d'abord, comme le ferait la première
    // instruction du programme (elle n'est en place qu'à la faute).
    let mut code = [0u8; 16];
    let mut code_ok = programme.memoire.servir(programme.entree, Acces::Lecture).is_ok()
        && programme.memoire.tables().lire(programme.entree, &mut code[..longueur]).is_ok()
        && code[..longueur] == attendu[..longueur];
    // Et celui de l'interpréteur, par où le programme commence : relu dans
    // l'espace, comparé à son fichier.
    if let (Some(i), Some(ouvert)) = (&images.interpreteur, &interpreteur) {
        let lire = |position: u64, tampon: &mut [u8]| vfs::lire(ouvert.numero, position, tampon) == tampon.len();
        let mut attendu = [0u8; 16];
        let longueur = i
            .segments()
            .find_map(|s| {
                let decalage = programme.depart.checked_sub(s.adresse).filter(|&d| d < s.taille_fichier)?;
                let longueur = (s.taille_fichier - decalage).min(16) as usize;
                lire(s.position + decalage, &mut attendu[..longueur]).then_some(longueur)
            })
            .unwrap_or(0);
        code_ok &= longueur > 0
            && programme.memoire.servir(programme.depart, Acces::Lecture).is_ok()
            && programme.memoire.tables().lire(programme.depart, &mut code[..longueur]).is_ok()
            && code[..longueur] == attendu[..longueur];
    }
    fermer_interpreteur(interpreteur.as_ref());
    // La copie de sa table des en-têtes est rendue tout de suite : elle ne
    // sert plus.
    drop(interpreteur);
    afficherln!("        en-tetes de programme a {:#x} ({} de {} octets), tas a partir de {:#x}, code en place : {}.",
                programme.adresse_entetes.unwrap_or(0), programme.nombre_entetes, programme.taille_entete,
                programme.memoire.debut_tas, if code_ok { "ok" } else { "ECHEC" });
    // Sa pile initiale : les arguments et l'environnement de sa ligne,
    // son chemin pour AT_EXECFN (comme Linux, le chemin donné à execve).
    let rsp = match pile::construire(&mut programme, lancement.arguments, lancement.environnement, chemin) {
        Ok(rsp) => rsp,
        Err(e) => refus!("[noyau] {} : pile initiale impossible : {}", nom, e),
    };
    // Son processus : avec la console en 0, 1 et 2 (/dev/null en 0 s'il
    // est lancé par `&`, comme sous sh), puis ses redirections, le dossier
    // courant du lanceur (la racine, ou celui d'un `cd`), l'umask de Linux,
    // et l'identité de l'utilisateur 1000. Un refus après l'ouverture de la
    // console ferme ce que la table tient déjà (Descripteurs::drop).
    let mut descripteurs = Descripteurs::new();
    if let Err(e) = appels_fichiers::ouvrir_console(&mut descripteurs) {
        refus!("[noyau] {} : pas de console (errno {})", nom, e.errno());
    }
    if lancement.fond {
        if let Err(e) = appels_fichiers::entree_sur_null(&mut descripteurs) {
            refus!("[noyau] {} : pas de /dev/null pour son entree (errno {})", nom, e.errno());
        }
    }
    // Ses redirections, dans l'ordre : chacune remplace ce qu'avait déjà ce
    // numéro (la console, /dev/null, une redirection précédente), sans
    // FD_CLOEXEC, comme sous sh.
    for &(fd, f) in lancement.entrees {
        if let Err(e) = appels_fichiers::installer_pour_le_noyau(&mut descripteurs, fd as u64, f) {
            refus!("[noyau] {} : pas de place pour son descripteur {} (errno {})", nom, fd, e.errno());
        }
    }
    let racine = vfs::avec(|fs, _| {
        let r = fs.racine();
        // Le dossier courant (celui du lanceur) et la racine tiennent chacun
        // leur inode.
        fs.prendre(r);
        if let Some(d) = lancement.dossier.tmpfs() {
            fs.prendre(d);
        }
        r
    });
    let (pml4, depart) = (programme.memoire.tables().pml4(), programme.depart);
    let pid = processus::numero_neuf();
    let entree = processus::ajouter(processus::Processus {
        pid,
        dossier: lancement.dossier,
        racine: Objet::Tmpfs(racine),
        umask: 0o022,
        identite,
        limites: processus::limites_par_defaut(),
        signaux: crate::signaux::Signaux::new(),
        fils: Vec::new(),
        fin_de_groupe: None,
    }, descripteurs, programme.memoire, nom);
    // Son exécutable, pour /proc/<pid>/exe (procfs.rs fabrique son dossier
    // d'après la table des processus) : son chemin, et son inode, tenu par
    // le lancement, puis par le lanceur jusqu'au recueil.
    processus::poser_exe(pid, copie(lancement.complet), n);
    let lance = entree.and_then(|e| tache::lancer_programme(nom, e.clone(), pml4, depart, rsp).map(|_| e));
    match lance {
        Some(processus) => {
            l.commencer();
            vfs::avec(|fs, _| fs.prendre(n));
            // Plus personne ne peut écrire le fichier tant qu'il s'exécute :
            // la protection prise à son ouverture reste, jusqu'au recueil.
            protection.garder();
            Some(Tache::Linux { processus, nom, fichier: n })
        }
        None => {
            afficherln!("[noyau] {} : plus de place pour sa tache ou son processus", nom);
            processus::recueillir(pid);
            drop(protection);
            None
        }
    }
}

/// Un interpréteur trouvé et vérifié (en-tête et table), en attendant
/// d'être chargé : son inode (tenu), son fichier ouvert (que tiendront
/// ses zones), sa taille, son en-tête et la copie de sa table.
struct Interpreteur {
    numero: Numero,
    fichier: crate::descripteurs::Fichier,
    taille: u64,
    entete: formats::elf::Entete,
    table: Vec<u8>,
}

/// Pourquoi un interpréteur ne peut pas servir.
enum EchecInterpreteur {
    /// Le trouver, l'exécuter, le protéger, l'ouvrir : l'erreur du système
    /// de fichiers, et ce qu'on essayait.
    Fichier(&'static str, fichiers::Erreur),
    /// Le lire : ce que dit le chargeur.
    Format(chargeur_elf::Refus),
}

impl EchecInterpreteur {
    /// L'errno que Linux rendrait (load_elf_binary) : celui du système de
    /// fichiers ; EIO si l'en-tête de 64 octets ne se lit pas en entier
    /// (elf_read) ; ELIBBAD pour le reste (pas ELF, autre machine, table
    /// des en-têtes illisible). Ce que Linux ne vérifie qu'après le point
    /// de non-retour (le genre, les segments : le processus est alors tué
    /// par SIGSEGV), ELIBBAD aussi : ici, tout est vérifié avant de rien
    /// charger, un écart voulu.
    fn errno(&self) -> i64 {
        match self {
            EchecInterpreteur::Fichier(_, e) => e.errno(),
            EchecInterpreteur::Format(chargeur_elf::Refus::Format(formats::elf::Erreur::Tronque)) => 5,
            EchecInterpreteur::Format(chargeur_elf::Refus::PlusDeMemoire) => 12,
            EchecInterpreteur::Format(_) => 80,
        }
    }
}

// Affiché par le noyau : sans accents.
impl fmt::Display for EchecInterpreteur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EchecInterpreteur::Fichier(quoi, _) => f.write_str(quoi),
            EchecInterpreteur::Format(e) => write!(f, "refuse : {e}"),
        }
    }
}

/// Trouve l'interpréteur `chemin`, comme Linux (`open_exec`, puis
/// `load_elf_binary`) : résolu depuis la racine (le dossier courant du
/// programme, aussi la racine), avec les droits de l'utilisateur 1000
/// (traverser, exécuter : EACCES sinon, et pour un dossier), ouvert
/// (IN_OPEN), protégé contre l'écriture (ETXTBSY s'il est ouvert en
/// écriture : refermé, IN_CLOSE_NOWRITE), puis lu par ses en-têtes
/// (IN_ACCESS). En cas d'échec, pourquoi ; rien ne reste tenu.
fn ouvrir_interpreteur(chemin: &[u8]) -> Result<Interpreteur, EchecInterpreteur> {
    use EchecInterpreteur::Fichier;
    let (n, complet, trouve) = appels_fichiers::trouver_pour(IDENTITE, chemin).map_err(|e| Fichier("introuvable", e))?;
    let lacher = || vfs::avec(|fs, cadres| fs.lacher(n, cadres));
    if let Err(e) = vfs::avec(|fs, _| fs.peut_executer(IDENTITE, n)) {
        lacher();
        return Err(Fichier("pas le droit de l'executer", e));
    }
    let fichier = match appels_fichiers::ouvrir_inode(n, chemin, complet, crate::descripteurs::Sorte::Fichier, &trouve) {
        Ok(f) => f,
        Err(e) => {
            lacher();
            return Err(Fichier("ouverture impossible", e));
        }
    };
    let fermer = || {
        vfs::avec_systeme(|s, cadres| s.lacher(fichier, cadres));
        lacher();
    };
    if let Err(e) = vfs::avec(|fs, _| fs.refuser_ecriture(n)) {
        fermer();
        return Err(Fichier("ouvert en ecriture", e));
    }
    let taille = vfs::avec(|fs, _| fs.attributs(n).taille);
    if taille > 0 {
        appels_fichiers::annoncer_la_lecture(fichier);
    }
    let lire = |position: u64, tampon: &mut [u8]| vfs::lire(n, position, tampon) == tampon.len();
    let (entete, table) = match chargeur_elf::verifier(taille, lire) {
        Ok(v) => v,
        Err(e) => {
            vfs::avec(|fs, _| fs.permettre_ecriture(n));
            fermer();
            return Err(EchecInterpreteur::Format(e));
        }
    };
    Ok(Interpreteur { numero: n, fichier, taille, entete, table })
}

/// La fin du chargement de l'interpréteur : son fichier ouvert lâché (ses
/// zones le tiennent), l'écriture de nouveau permise (seul le programme
/// reste protégé pendant qu'il tourne, comme chez Linux), son inode lâché.
fn fermer_interpreteur(interpreteur: Option<&Interpreteur>) {
    if let Some(i) = interpreteur {
        vfs::avec_systeme(|s, cadres| s.lacher(i.fichier, cadres));
        vfs::avec(|fs, cadres| {
            fs.permettre_ecriture(i.numero);
            fs.lacher(i.numero, cadres);
        });
    }
}

/// Un programme WebAssembly : on lit son module, puis, dans une tâche du
/// noyau à lui (tache.rs), on le décode, le valide, l'instancie avec WASI,
/// et on appelle son point d'entrée _start par tranches de carburant.
/// Les interruptions de l'horloge et du clavier, elles, continuent
/// d'arriver pendant tout ce temps, même pendant une écriture du programme
/// (la console écrit par petits paquets). La tâche reçoit des copies de ce
/// qu'elle utilise (ses arguments, son environnement, ses dossiers) : elle
/// ne dépend plus de la ligne de /etc/demarrage, et pourra tourner pendant
/// que le lanceur passe à la suivante.
fn executer_wasm(l: &mut Lanceur, nom: NomCourt, n: Numero, lancement: &Lancement) -> Option<Tache> {
    // Un refus : le dire, et rien n'est lancé.
    macro_rules! refus {
        ($($t:tt)*) => {{
            afficherln!($($t)*);
            return None;
        }};
    }
    // L'interpréteur veut le module d'un seul tenant : il est lu dans un
    // bloc du tas, qui fait au plus 4 Mio (tas.rs) ; un module plus gros est
    // refusé, jusqu'à ce que le noyau sache projeter des pages éparses d'un
    // seul tenant (vmalloc).
    let taille = vfs::avec(|fs, _| fs.attributs(n).taille) as usize;
    let Ok(mut octets) = faillible::remplie(taille, 0) else {
        refus!("[noyau] {} : module WebAssembly de {} octets, trop gros pour le tas", nom, taille);
    };
    if vfs::lire(n, 0, &mut octets) != taille {
        refus!("[noyau] {} : module WebAssembly illisible", nom);
    }
    let (Some(arguments), Some(environnement), Some(dossiers)) =
        (copies(lancement.arguments), copies(lancement.environnement), copies(lancement.dossiers))
    else {
        refus!("[noyau] {} : plus de memoire pour ses arguments", nom);
    };
    // Ses écoutes, ici, avant sa tâche (wasi::Ecoutes) : la ligne suivante
    // les trouve déjà. Une écoute impossible refuse la ligne ; celles déjà
    // ouvertes sont alors fermées (en disparaissant avec `ecoutes`).
    let mut ecoutes = wasi::Ecoutes::new();
    for &(adresse, port, mot) in lancement.ecoutes {
        if let Err(e) = ecoutes.ouvrir(IDENTITE, adresse, port) {
            refus!("[noyau] {} : --tcplisten={} impossible (errno {})", nom, Nom(mot), -e);
        }
    }
    let lancee = tache::lancer_noyau(nom, move || {
        let (Some(a), Some(e), Some(d)) = (tranches(&arguments), tranches(&environnement), tranches(&dossiers)) else {
            return afficherln!("[noyau] {} : plus de memoire pour ses arguments", nom);
        };
        executer_module(nom, &octets, &a, &e, &d, ecoutes)
    });
    match lancee {
        Some(t) => {
            l.commencer();
            Some(Tache::Wasm(t))
        }
        None => refus!("[noyau] {} : pas de pile noyau pour sa tache", nom),
    }
}

/// Des copies des chaînes de `chaines`, dans le tas ; None s'il n'y a pas
/// la place.
fn copies(chaines: &[&[u8]]) -> Option<Vec<Vec<u8>>> {
    let mut v = faillible::avec_capacite(chaines.len()).ok()?;
    for c in chaines {
        v.ajouter_dans_la_place(faillible::copie(c).ok()?);
    }
    Some(v)
}

/// Les tranches des chaînes de `v` (un petit tableau de pointeurs, quelques
/// dizaines d'octets) ; None s'il n'y a pas la place.
fn tranches(v: &[Vec<u8>]) -> Option<Vec<&[u8]>> {
    let mut t = faillible::avec_capacite(v.len()).ok()?;
    v.iter().for_each(|c| t.ajouter_dans_la_place(c.as_slice()));
    Some(t)
}

/// Le corps d'un programme WebAssembly, dans sa tâche (voir
/// `executer_wasm`).
fn executer_module(nom: NomCourt, octets: &[u8], arguments: &[&[u8]], environnement: &[&[u8]], dossiers: &[&[u8]],
                   ecoutes: wasi::Ecoutes) {
    use wasm::{Etat, Externe, Magasin, Piege};

    const TRANCHE: u64 = 1000;

    let module = match wasm::decoder(octets).and_then(wasm::valider) {
        // La bibliothèque wasm prend son module dans l'Arc de alloc (son
        // interface, testée aussi sur l'hôte) : une allocation qui peut
        // encore faire paniquer le noyau, comme celles de la bibliothèque
        // elle-même (une dette, dans « Reste à faire »).
        #[allow(clippy::disallowed_methods)]
        Ok(m) => alloc::sync::Arc::new(m),
        Err(e) => return afficherln!("[noyau] {} : programme WebAssembly refuse : {}", nom, e),
    };
    afficherln!("[noyau] {} : programme WebAssembly, {} octets, decode et valide.", nom, octets.len());
    // Son budget de mémoire : 16 Mio pour ses tables et sa mémoire, chacune
    // d'au plus 4 Mio (un bloc du tas, voir tas.rs).
    let mut magasin = Magasin::avec_budget(16 << 20);
    tache::courante().marquer_webassembly();
    // Ses descripteurs : la console, les dossiers pré-ouverts de sa ligne et
    // ses écoutes ; ses arguments et son environnement.
    let mut hote = match wasi::Wasi::new(IDENTITE, dossiers, ecoutes, arguments, environnement) {
        Ok(h) => h,
        Err((e, Some(dossier))) => {
            return afficherln!("[noyau] {} : --dir={} impossible (errno {})", nom, Nom(dossier), e.errno());
        }
        Err((e, None)) => return afficherln!("[noyau] {} : pas de descripteurs (errno {})", nom, e.errno()),
    };
    let imports = match wasi::imports(&mut magasin, &module) {
        Ok(i) => i,
        Err(e) => return afficherln!("[noyau] {} : programme non liable : {}", nom, e),
    };
    let instance = match magasin.instancier(module, &imports) {
        Ok(i) if i.demarrage.is_none() => i.instance,
        Ok(_) => return afficherln!("[noyau] {} : programme refuse, fonction de demarrage inattendue", nom),
        Err(e) => return afficherln!("[noyau] {} : programme non instanciable : {}", nom, e),
    };
    let Some(Externe::Fonction(debut)) = magasin.exporte(instance, "_start") else {
        return afficherln!("[noyau] {} : programme sans _start", nom);
    };
    // WASI veut un _start de type [] -> [] : un programme qui en attend des
    // arguments est refusé, comme le reste, sans que le noyau s'arrête.
    let Ok(mut execution) = magasin.preparer(debut, &[]) else {
        return afficherln!("[noyau] {} : programme refuse, _start doit etre de type [] -> []", nom);
    };
    let (mut tranches, mut consomme) = (0u64, 0u64);
    let fin = loop {
        let mut carburant = TRANCHE;
        let etat = execution.reprendre(&mut magasin, &mut hote, &mut carburant);
        tranches += 1;
        consomme += TRANCHE - carburant;
        match etat {
            Ok(Etat::Interrompue) => continue,
            autre => break autre,
        }
    };
    let code = match fin {
        // proc_exit(code), ou _start qui revient sans l'appeler : code 0.
        Err(Piege::Hote(code)) => code,
        Ok(_) => 0,
        Err(p) => return afficherln!("[noyau] {} : programme arrete par un piege : {}", nom, p),
    };
    afficherln!("[noyau] {} : termine, code de sortie {}, {} unites de carburant en {} tranches.",
                nom, code, consomme, tranches);
}
