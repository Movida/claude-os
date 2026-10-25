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
//! Options écartées :
//!   - un seul étage (le numéro désigne directement l'inode et la
//!     position) : `dup` ne partagerait pas la position, ce que POSIX
//!     exige (deux processus qui écrivent à la suite dans le même journal) ;
//!   - des `Rc` pour les fichiers ouverts : leur allocation ne sait pas
//!     échouer, et une allocation demandée par un programme doit pouvoir
//!     rendre ENOMEM. Une table à index, avec un compteur explicite.
//! Les sortes à venir : les tubes, eventfd et epoll (6f), les sockets (6h),
//! les fichiers de /proc (6d). Une sorte de plus, ce sera une ligne de
//! plus dans chaque `match` des appels (appels_fichiers.rs).

use alloc::vec::Vec;

use fichiers::tmpfs::Ouvert;

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
    /// depuis 5.6).
    Aleatoire,
    /// /dev/console : l'écran et le port série. Pas encore un terminal
    /// (6j) : la lecture rend « fin de fichier ».
    Console,
}

/// Un fichier ouvert (la `struct file`).
pub struct FichierOuvert {
    pub sorte: Sorte,
    /// Ce qu'a rendu le tmpfs : l'inode, et si l'ouverture compte parmi ses
    /// écrivains.
    pub ouvert: Ouvert,
    pub lecture: bool,
    pub ecriture: bool,
    /// Les drapeaux d'état qui restent (O_APPEND, O_NONBLOCK...), comme
    /// les rend F_GETFL.
    pub drapeaux: u32,
    /// La position (pour un dossier : celle de `lire_dossier`).
    pub position: u64,
    /// Combien le tiennent : ses descripteurs, et les zones qui le
    /// projettent.
    references: u32,
}

impl FichierOuvert {
    pub fn new(sorte: Sorte, ouvert: Ouvert, lecture: bool, ecriture: bool, drapeaux: u32) -> FichierOuvert {
        FichierOuvert { sorte, ouvert, lecture, ecriture, drapeaux, position: 0, references: 1 }
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

    /// Le fichier est tenu une fois de plus (dup).
    pub fn prendre(&mut self, f: Fichier) {
        self.fichier(f).references += 1;
    }

    /// Le fichier est tenu une fois de moins : au dernier, il est retiré
    /// de la table, et rendu à l'appelant pour qu'il le ferme (qu'il rende
    /// l'inode au tmpfs). Une table vide rend sa mémoire.
    pub fn lacher(&mut self, f: Fichier) -> Option<FichierOuvert> {
        let fichier = self.fichier(f);
        fichier.references -= 1;
        if fichier.references > 0 {
            return None;
        }
        let ferme = self.cases[f.0 as usize].take();
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

/// Les descripteurs d'un processus (la `files_struct` de Linux).
pub struct Descripteurs {
    cases: Vec<Option<Descripteur>>,
    /// RLIMIT_NOFILE : (courante, dure). Aucun descripteur à cette valeur
    /// ou au-delà.
    pub limite: (u64, u64),
}

impl Descripteurs {
    pub fn new() -> Descripteurs {
        Descripteurs { cases: Vec::new(), limite: LIMITE_DESCRIPTEURS }
    }

    /// Le descripteur `fd`, s'il est ouvert. Linux ne regarde que les 32
    /// bits bas (un `unsigned int`).
    pub fn get(&self, fd: u64) -> Option<Descripteur> {
        self.cases.get(fd as u32 as usize).copied().flatten()
    }

    pub fn get_mut(&mut self, fd: u64) -> Option<&mut Descripteur> {
        self.cases.get_mut(fd as u32 as usize).and_then(Option::as_mut)
    }

    /// Le plus petit numéro libre, `minimum` ou au-delà, sous la limite.
    pub fn libre(&self, minimum: u64) -> Option<u64> {
        (minimum..self.limite.0).find(|&fd| self.get(fd).is_none())
    }

    /// Range `d` au numéro `fd` (libre, sous la limite). ENOMEM si la
    /// table ne peut pas grandir : rien n'a changé.
    pub fn installer(&mut self, fd: u64, d: Descripteur) -> Result<(), ()> {
        let ancien = self.remplacer(fd, d)?;
        debug_assert!(ancien.is_none(), "installer sur un descripteur ouvert");
        Ok(())
    }

    /// Range `d` au numéro `fd` (sous la limite), à la place de celui qui y
    /// était, rendu : à l'appelant de lâcher son fichier (dup2). ENOMEM si
    /// la table ne peut pas grandir : rien n'a changé.
    pub fn remplacer(&mut self, fd: u64, d: Descripteur) -> Result<Option<Descripteur>, ()> {
        let i = fd as usize;
        if i >= self.cases.len() {
            self.cases.try_reserve(i + 1 - self.cases.len()).map_err(|_| ())?;
            self.cases.resize(i + 1, None);
        }
        Ok(self.cases[i].replace(d))
    }

    /// Retire le descripteur `fd` : à l'appelant de lâcher son fichier.
    pub fn retirer(&mut self, fd: u64) -> Option<Descripteur> {
        let d = self.cases.get_mut(fd as u32 as usize)?.take();
        while self.cases.last().is_some_and(Option::is_none) {
            self.cases.pop();
        }
        if self.cases.is_empty() {
            self.cases = Vec::new();
        }
        d
    }

    /// Les numéros des descripteurs ouverts dans [premier, dernier].
    pub fn ouverts(&self, premier: u64, dernier: u64) -> impl Iterator<Item = u64> + '_ {
        let fin = (self.cases.len() as u64).min(dernier.saturating_add(1));
        (premier..fin).filter(|&fd| self.get(fd).is_some())
    }
}
