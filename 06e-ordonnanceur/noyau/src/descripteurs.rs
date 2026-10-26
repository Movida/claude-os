//! Les fichiers ouverts et les descripteurs : ce que désigne le « 3 » d'un
//! `read(3, ...)`.
//!
//! Deux étages, comme dans Linux :
//!   - le FICHIER OUVERT (la `struct file`) : ce qu'a créé un `open`. Il
//!     tient l'inode, la position dans le fichier, le mode d'ouverture
//!     (lecture, écriture, O_APPEND, O_NONBLOCK), et sa SORTE, qui dit ce
//!     que font read, write, lseek... sur lui (les `file_operations` de
//!     Linux : un fichier du tmpfs, un dossier, /dev/null, la console...).
//!     Il est partagé : `dup` en fait un second descripteur, avec la même
//!     position (fork en fera autant, en 6k). Il vit tant qu'on le tient
//!     (un compteur), dans une table du noyau (`Ouverts`) ;
//!   - le DESCRIPTEUR : un petit nombre propre à un processus (la
//!     `files_struct` de Linux), qui désigne un fichier ouvert, avec un
//!     seul drapeau à lui, « fermer à l'exec » (FD_CLOEXEC). Le plus petit
//!     numéro libre est toujours pris, comme le veut POSIX : c'est ce qui
//!     permet le vieux `close(1); open(...)` des shells.
//! Un appel système qui se sert d'un descripteur TIENT son fichier ouvert
//! jusqu'à sa fin (appels_fichiers::FichierTenu, le `fdget` de Linux) : un
//! autre fil du programme peut fermer le descripteur pendant ce temps, le
//! fichier ne disparaîtra qu'à la fin de l'appel.
//! Options écartées :
//!   - un seul étage (le numéro désigne directement l'inode et la
//!     position) : `dup` ne partagerait pas la position, ce que POSIX
//!     exige (deux processus qui écrivent à la suite dans le même journal) ;
//!   - des `Rc` pour les fichiers ouverts : leur allocation ne sait pas
//!     échouer, et une allocation demandée par un programme doit pouvoir
//!     rendre ENOMEM. Une table à index, avec un compteur explicite.
//! Les sortes à venir : les tubes (6f), les sockets (6h). Une sorte de
//! plus, ce sera une ligne de plus dans chaque `match` des appels
//! (appels_fichiers.rs). Certaines ont des données à elles (le compteur
//! d'un eventfd, la liste d'un epoll, la source d'un fichier de /proc :
//! `Donnees`).

use alloc::vec::Vec;

use crate::programmes::NomCourt;
use fichiers::montages::Objet;
use fichiers::noyaufs::Sequence;
use fichiers::tmpfs::{Numero, Ouvert};

/// Ce que font les appels sur un fichier ouvert (les file_operations).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sorte {
    /// Un fichier ordinaire du tmpfs : ses pages.
    Fichier,
    /// Un dossier : getdents64, pas read.
    Dossier,
    /// Ouvert avec O_PATH : ni lecture ni écriture, seulement un point de
    /// départ (fstat, fchdir, les appels *at).
    Chemin,
    /// /dev/null : rien à lire, tout s'écrit dans le vide.
    Null,
    /// /dev/zero : des zéros à lire, tout s'écrit dans le vide.
    Zero,
    /// /dev/full : des zéros à lire, plus de place pour écrire (ENOSPC).
    Plein,
    /// /dev/random et /dev/urandom : de l'aléa (le même, comme Linux
    /// depuis 5.6). Seul /dev/random (`random`) sait dire « prêt » à epoll
    /// (il attendait jadis que la réserve d'aléa soit pleine).
    Aleatoire { random: bool },
    /// /dev/console : l'écran et le port série. Pas encore un terminal
    /// (6j) : la lecture rend « fin de fichier ».
    Console,
    /// Un compteur que se partagent ceux qui s'attendent (eventfd, 6d) :
    /// ses données dans `Donnees::EventFd`.
    EventFd,
    /// Une liste de fichiers à surveiller (epoll, 6d) : `Donnees::Epoll`.
    Epoll,
    /// Un fichier d'un système du noyau (/proc, /sys, 6d), dont le contenu
    /// est fabriqué à la lecture (`Donnees::Noyau`), d'une des trois façons
    /// de Linux.
    Noyau { lecture: Lecture },
}

/// Comment se lit un fichier d'un système du noyau (mesuré sous Linux
/// 6.18 : trois comportements).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lecture {
    /// Des enregistrements, comme le `seq_file` de Linux (/proc/<pid>/maps,
    /// statm) : se lit par morceaux, à toute position ; lseek SEEK_SET et
    /// SEEK_CUR seulement.
    Sequence,
    /// Une valeur de /proc/sys (`proc_dointvec`) : tout d'un coup à la
    /// position 0, rien ailleurs ; lseek de `default_llseek`, d'un fichier
    /// de taille nulle.
    Valeur,
    /// Un attribut de sysfs (kernfs) : comme une séquence d'un seul
    /// enregistrement, mais lseek de `generic_file_llseek`, d'un fichier
    /// d'une page.
    Attribut,
}

impl Sorte {
    /// Ce fichier sait-il dire s'il est prêt, et réveiller qui l'attend (il
    /// a une opération `poll`, le `file_can_poll` de Linux) ? Seuls ceux-là
    /// peuvent être surveillés par epoll (EPERM sinon). Un fichier ordinaire
    /// ou un dossier est toujours prêt : on ne le surveille pas. Mesuré sous
    /// Linux 6.18 : /dev/null, /dev/zero, /dev/full et /dev/urandom refusés,
    /// /dev/random et les terminaux acceptés.
    pub fn sait_attendre(self) -> bool {
        matches!(self, Sorte::Aleatoire { random: true } | Sorte::Console | Sorte::EventFd | Sorte::Epoll
                       | Sorte::Noyau { lecture: Lecture::Valeur | Lecture::Attribut })
    }
}

/// Les données propres à certaines sortes de fichiers ouverts.
pub enum Donnees {
    Aucune,
    /// Le compteur d'un eventfd, EFD_SEMAPHORE (une lecture n'en prend
    /// qu'un), et les tâches qui attendent qu'il change (evenements.rs).
    EventFd { compteur: u64, semaphore: bool, attente: crate::attente::FileAttente },
    /// Ce que surveille un epoll.
    Epoll(Vec<Interet>),
    /// D'où vient le contenu d'un fichier d'un système du noyau (une source
    /// du noyau et son argument : procfs.rs), et où en est sa lecture.
    Noyau { source: u32, argument: u32, sequence: Sequence },
}

/// Une inscription dans un epoll (l'`epitem` de Linux) : le couple (fichier
/// ouvert, numéro de descripteur) qui l'identifie, comme Linux (mesuré :
/// après un dup puis la fermeture du premier numéro, l'inscription reste,
/// au nom du premier), les événements demandés et la donnée que le
/// programme veut voir revenir.
#[derive(Clone, Copy, Debug)]
pub struct Interet {
    pub fichier: Fichier,
    pub fd: u32,
    pub evenements: u32,
    pub donnees: u64,
}

/// Ce que tient un fichier ouvert : un inode du tmpfs, avec ce qu'a rendu
/// son ouverture (s'il compte parmi ses écrivains), ou un objet d'un
/// système de fichiers du noyau (6d : rien à rendre, ses inodes sont au
/// noyau).
#[derive(Clone, Copy, Debug)]
pub enum Tenu {
    Tmpfs(Ouvert),
    Noyau(Objet),
}

/// Un fichier ouvert (la `struct file`).
pub struct FichierOuvert {
    pub sorte: Sorte,
    pub tenu: Tenu,
    pub lecture: bool,
    pub ecriture: bool,
    /// Les drapeaux d'état qui restent (O_APPEND, O_NONBLOCK...), comme
    /// les rend F_GETFL.
    pub drapeaux: u32,
    /// La position (pour un dossier : celle de `lire_dossier`).
    pub position: u64,
    /// Ce qui est propre à sa sorte (eventfd, epoll).
    pub donnees: Donnees,
    /// Le nom de base du chemin par lequel il a été ouvert, pour les
    /// messages (« dans libc.so.6[...] »).
    pub nom: NomCourt,
    /// Son chemin absolu et canonique (le `d_path` de Linux), calculé à
    /// l'ouverture : celui que montre /proc/self/maps. Vide s'il n'a pas pu
    /// l'être (plus de PATH_MAX octets, plus de mémoire) : ouvrir ne doit
    /// pas échouer pour un nom. Linux le recalcule à chaque lecture (un
    /// renommage s'y voit) ; nous gardons celui de l'ouverture, un écart
    /// voulu : il faudrait au tmpfs le parent de chaque fichier, qu'un lien
    /// physique rend ambigu (Linux tient le `dentry` de l'ouverture).
    pub chemin: Vec<u8>,
    /// Combien le tiennent : ses descripteurs, les zones qui le projettent,
    /// et les appels système qui s'en servent (appels_fichiers::FichierTenu).
    references: u32,
}

impl FichierOuvert {
    pub fn new(sorte: Sorte, tenu: Tenu, lecture: bool, ecriture: bool, drapeaux: u32, chemin: &[u8]) -> FichierOuvert {
        let nom = NomCourt::de(chemin.rsplit(|&o| o == b'/').find(|n| !n.is_empty()).unwrap_or(chemin));
        FichierOuvert { sorte, tenu, lecture, ecriture, drapeaux, position: 0, donnees: Donnees::Aucune, nom, chemin: Vec::new(), references: 1 }
    }

    /// Le même, avec son chemin canonique.
    pub fn avec_chemin(mut self, chemin: Vec<u8>) -> FichierOuvert {
        self.chemin = chemin;
        self
    }

    /// L'objet ouvert, dans la vue de tous les systèmes de fichiers.
    pub fn objet(&self) -> Objet {
        match self.tenu {
            Tenu::Tmpfs(o) => Objet::Tmpfs(o.numero),
            Tenu::Noyau(o) => o,
        }
    }

    /// Son inode du tmpfs, s'il en est un.
    pub fn numero(&self) -> Option<Numero> {
        match self.tenu {
            Tenu::Tmpfs(o) => Some(o.numero),
            Tenu::Noyau(_) => None,
        }
    }

    /// L'inode du tmpfs d'un fichier dont la sorte ne vient que du tmpfs (un
    /// fichier ordinaire, un périphérique de /dev) : l'ouverture l'a choisie
    /// ainsi (appels_fichiers::sorte).
    pub fn inode(&self) -> Numero {
        self.numero().expect("une sorte du tmpfs sur un objet d'un systeme monte")
    }
}

/// Le numéro d'un fichier ouvert dans la table du noyau.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fichier(u32);

impl Fichier {
    /// Le numéro tel que le garde une zone de fichier (../zones).
    pub fn de(numero: u32) -> Fichier {
        Fichier(numero)
    }

    pub fn numero(self) -> u32 {
        self.0
    }
}

/// La table des fichiers ouverts, sous le verrou du système de fichiers
/// (vfs.rs).
#[derive(Default)]
pub struct Ouverts {
    cases: Vec<Option<FichierOuvert>>,
}

impl Ouverts {
    /// Range un fichier ouvert neuf (tenu une fois). ENOMEM si la table ne
    /// peut pas grandir.
    pub fn ajouter(&mut self, f: FichierOuvert) -> Result<Fichier, FichierOuvert> {
        if let Some(i) = self.cases.iter().position(Option::is_none) {
            self.cases[i] = Some(f);
            return Ok(Fichier(i as u32));
        }
        if self.cases.try_reserve(1).is_err() {
            return Err(f);
        }
        self.cases.push(Some(f));
        Ok(Fichier(self.cases.len() as u32 - 1))
    }

    pub fn fichier(&mut self, f: Fichier) -> &mut FichierOuvert {
        self.cases[f.0 as usize].as_mut().expect("fichier ouvert disparu")
    }

    /// L'epoll `depuis` surveille-t-il `cherche`, directement ou par un
    /// epoll qu'il surveille ? (Pour refuser une boucle : ELOOP.)
    pub fn surveille(&self, depuis: Fichier, cherche: Fichier) -> bool {
        // Un parcours en profondeur, sans récursion (la pile du noyau est
        // petite), borné par le nombre de fichiers ouverts : chacun n'est
        // vu qu'une fois.
        let mut vus = Vec::new();
        let mut a_voir = Vec::new();
        if a_voir.try_reserve(1).is_err() {
            return true;
        }
        a_voir.push(depuis);
        while let Some(f) = a_voir.pop() {
            if f == cherche {
                return true;
            }
            if vus.contains(&f) || vus.try_reserve(1).is_err() {
                continue;
            }
            vus.push(f);
            if let Some(Some(FichierOuvert { donnees: Donnees::Epoll(interets), .. })) = self.cases.get(f.0 as usize) {
                for i in interets {
                    if a_voir.try_reserve(1).is_err() {
                        return true;
                    }
                    a_voir.push(i.fichier);
                }
            }
        }
        false
    }

    /// La plus longue chaîne d'epoll sous l'epoll `f` (ceux qu'il
    /// surveille, puis ceux qu'ils surveillent...), ou au-dessus de lui
    /// (ceux qui le surveillent...), en nombre d'étages, sans compter `f` :
    /// le `ep_loop_check_proc` et le `ep_get_upwards_depth_proc` de Linux.
    /// Étage par étage, sans récursion ; au-delà de `limite` étages, on
    /// s'arrête (la réponse est déjà « trop »). None : plus de mémoire.
    /// Il n'y a pas de boucle (`surveille` les refuse) : le parcours finit.
    pub fn etages(&self, f: Fichier, vers_le_bas: bool, limite: u32) -> Option<u32> {
        let epoll = |g: Fichier| match self.cases.get(g.0 as usize) {
            Some(Some(FichierOuvert { donnees: Donnees::Epoll(interets), .. })) => Some(interets),
            _ => None,
        };
        let mut etage = Vec::new();
        etage.try_reserve(1).ok()?;
        etage.push(f);
        let mut n = 0;
        while n <= limite {
            let mut suivant: Vec<Fichier> = Vec::new();
            let mut ajouter = |g: Fichier| -> Option<()> {
                if epoll(g).is_some() && !suivant.contains(&g) {
                    suivant.try_reserve(1).ok()?;
                    suivant.push(g);
                }
                Some(())
            };
            for &g in &etage {
                if vers_le_bas {
                    for i in epoll(g).into_iter().flatten() {
                        ajouter(i.fichier)?;
                    }
                } else {
                    for (h, case) in self.cases.iter().enumerate() {
                        if let Some(FichierOuvert { donnees: Donnees::Epoll(interets), .. }) = case
                            && interets.iter().any(|i| i.fichier == g)
                        {
                            ajouter(Fichier(h as u32))?;
                        }
                    }
                }
            }
            if suivant.is_empty() {
                break;
            }
            n += 1;
            etage = suivant;
        }
        Some(n)
    }

    /// Le fichier est tenu une fois de plus (dup).
    pub fn prendre(&mut self, f: Fichier) {
        self.fichier(f).references += 1;
    }

    /// Le fichier est tenu une fois de moins : au dernier, il est retiré
    /// de la table, et rendu à l'appelant pour qu'il le ferme (qu'il rende
    /// l'inode au tmpfs). Une table vide rend sa mémoire. Un fichier fermé
    /// quitte aussi les epoll qui le surveillaient (le `eventpoll_release`
    /// de Linux) : une inscription ne tient pas le fichier, et son numéro
    /// servira à un autre.
    pub fn lacher(&mut self, f: Fichier) -> Option<FichierOuvert> {
        let fichier = self.fichier(f);
        fichier.references -= 1;
        if fichier.references > 0 {
            return None;
        }
        let ferme = self.cases[f.0 as usize].take();
        for case in self.cases.iter_mut().flatten() {
            if let Donnees::Epoll(interets) = &mut case.donnees {
                interets.retain(|i| i.fichier != f);
            }
        }
        while self.cases.last().is_some_and(Option::is_none) {
            self.cases.pop();
        }
        if self.cases.is_empty() {
            self.cases = Vec::new();
        }
        ferme
    }
}

/// Un descripteur : le fichier ouvert qu'il désigne, et son drapeau.
#[derive(Clone, Copy, Debug)]
pub struct Descripteur {
    pub fichier: Fichier,
    /// FD_CLOEXEC : fermé par execve (6k).
    pub fermer_a_l_exec: bool,
}

/// La limite du nombre de descripteurs (RLIMIT_NOFILE) de Linux par défaut
/// : 1024, que le programme peut relever jusqu'à 4096 (la limite dure).
pub const LIMITE_DESCRIPTEURS: (u64, u64) = (1024, 4096);

/// Une case de la table des descripteurs.
#[derive(Clone, Copy, Debug)]
enum Case {
    Libre,
    /// Prise par un appel en cours (openat, dup, eventfd...), qui y
    /// installera son fichier : le numéro n'est plus libre, mais rien ne s'y
    /// lit encore. C'est l'état d'un numéro entre le `get_unused_fd_flags` et
    /// le `fd_install` de Linux : un autre fil qui s'en sert entre les deux
    /// reçoit EBADF (pas de fichier), et un `dup2` vers lui EBUSY.
    Reservee,
    Ouverte(Descripteur),
}

/// Pourquoi la table refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refus {
    /// Plus de numéro libre sous la limite (EMFILE).
    PlusDeNumero,
    /// La table ne peut pas grandir (ENOMEM).
    PlusDeMemoire,
    /// Le numéro est réservé par un appel en cours (EBUSY, pour dup2).
    Reserve,
}

/// Les descripteurs d'un processus (la `files_struct` de Linux).
///
/// Un numéro s'obtient en deux temps, comme dans Linux : RÉSERVÉ
/// (`reserver`, le plus petit libre, la table agrandie s'il le faut), puis
/// le fichier INSTALLÉ (`installer`, qui ne peut plus échouer). Entre les
/// deux, l'appel fait ce qui peut échouer (résoudre un chemin, ouvrir), et
/// rend le numéro s'il échoue (`liberer`). Choisir le numéro et l'occuper
/// dans la même section est ce qui empêche deux fils qui ouvrent en même
/// temps de recevoir le même. Option écartée : chercher un numéro libre
/// (sans le prendre) au début, et installer à la fin, comme jusqu'à 6d ;
/// avec un seul fil, personne ne pouvait le prendre entre les deux.
pub struct Descripteurs {
    cases: Vec<Case>,
    /// RLIMIT_NOFILE : (courante, dure). Aucun descripteur à cette valeur
    /// ou au-delà.
    pub limite: (u64, u64),
}

impl Descripteurs {
    pub fn new() -> Descripteurs {
        Descripteurs { cases: Vec::new(), limite: LIMITE_DESCRIPTEURS }
    }

    /// La case `fd` (libre au-delà de la fin de la table). Linux ne regarde
    /// que les 32 bits bas d'un numéro (un `unsigned int`).
    fn case(&self, fd: u64) -> Case {
        self.cases.get(fd as u32 as usize).copied().unwrap_or(Case::Libre)
    }

    /// Le descripteur `fd`, s'il est ouvert (pas s'il est seulement réservé).
    pub fn get(&self, fd: u64) -> Option<Descripteur> {
        match self.case(fd) {
            Case::Ouverte(d) => Some(d),
            Case::Libre | Case::Reservee => None,
        }
    }

    pub fn get_mut(&mut self, fd: u64) -> Option<&mut Descripteur> {
        match self.cases.get_mut(fd as u32 as usize) {
            Some(Case::Ouverte(d)) => Some(d),
            _ => None,
        }
    }

    /// La table, assez grande pour la case `fd` ; ENOMEM si elle ne peut pas
    /// grandir (rien n'a changé).
    fn agrandir(&mut self, fd: u64) -> Result<(), Refus> {
        let i = fd as usize;
        if i >= self.cases.len() {
            self.cases.try_reserve(i + 1 - self.cases.len()).map_err(|_| Refus::PlusDeMemoire)?;
            self.cases.resize(i + 1, Case::Libre);
        }
        Ok(())
    }

    /// Réserve le plus petit numéro libre, `minimum` ou au-delà, sous la
    /// limite (le `alloc_fd` de Linux) : EMFILE s'il n'y en a plus, ENOMEM si
    /// la table ne peut pas grandir.
    pub fn reserver(&mut self, minimum: u64) -> Result<u64, Refus> {
        let fd = (minimum..self.limite.0).find(|&fd| matches!(self.case(fd), Case::Libre)).ok_or(Refus::PlusDeNumero)?;
        self.agrandir(fd)?;
        self.cases[fd as usize] = Case::Reservee;
        Ok(fd)
    }

    /// Installe `d` au numéro `fd`, réservé par `reserver` (le `fd_install`
    /// de Linux) : la table a déjà sa place, rien ne peut échouer. Sur une
    /// case qui n'est pas réservée, c'est une erreur du noyau : on s'arrête
    /// (le `BUG_ON` de Linux), plutôt que d'écraser un descripteur ouvert
    /// dont le fichier ne serait jamais lâché.
    pub fn installer(&mut self, fd: u64, d: Descripteur) {
        let case = &mut self.cases[fd as usize];
        assert!(matches!(case, Case::Reservee), "installer sur un numero non reserve");
        *case = Case::Ouverte(d);
    }

    /// Rend le numéro réservé `fd`, sans fichier installé (l'appel a échoué
    /// : le `put_unused_fd` de Linux).
    pub fn liberer(&mut self, fd: u64) {
        let case = &mut self.cases[fd as usize];
        assert!(matches!(case, Case::Reservee), "liberer un numero non reserve");
        *case = Case::Libre;
        self.rogner();
    }

    /// Range `d` au numéro `fd` (sous la limite), à la place de celui qui y
    /// était, rendu : à l'appelant de lâcher son fichier (dup2). Un numéro
    /// réservé par un autre appel : EBUSY (le `do_dup2` de Linux) ; ENOMEM si
    /// la table ne peut pas grandir. Rien n'a changé en cas de refus.
    pub fn remplacer(&mut self, fd: u64, d: Descripteur) -> Result<Option<Descripteur>, Refus> {
        self.agrandir(fd)?;
        let case = &mut self.cases[fd as usize];
        match core::mem::replace(case, Case::Ouverte(d)) {
            Case::Libre => Ok(None),
            Case::Ouverte(ancien) => Ok(Some(ancien)),
            Case::Reservee => {
                *case = Case::Reservee;
                Err(Refus::Reserve)
            }
        }
    }

    /// Retire le descripteur ouvert `fd` (pas un numéro seulement réservé :
    /// close y voit EBADF, comme Linux) : à l'appelant de lâcher son fichier.
    pub fn retirer(&mut self, fd: u64) -> Option<Descripteur> {
        let case = self.cases.get_mut(fd as u32 as usize)?;
        let Case::Ouverte(d) = *case else { return None };
        *case = Case::Libre;
        self.rogner();
        Some(d)
    }

    /// Les cases libres de la fin rendues ; une table vide rend sa mémoire
    /// (le contrôle « memoire rendue » des programmes le verrait).
    fn rogner(&mut self) {
        while self.cases.last().is_some_and(|c| matches!(c, Case::Libre)) {
            self.cases.pop();
        }
        if self.cases.is_empty() {
            self.cases = Vec::new();
        }
    }

    /// Les numéros des descripteurs ouverts dans [premier, dernier].
    pub fn ouverts(&self, premier: u64, dernier: u64) -> impl Iterator<Item = u64> + '_ {
        let fin = (self.cases.len() as u64).min(dernier.saturating_add(1));
        (premier..fin).filter(|&fd| self.get(fd).is_some())
    }
}
