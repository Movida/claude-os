//! epoll : attendre que des fichiers soient prêts, sans les resonder tous à
//! chaque fois (fs/eventpoll.c de Linux 6.18, que ce module suit pas à pas).
//!
//! `poll` sonde chacun de ses fichiers à chaque appel, et ses entrées ne
//! vivent que le temps de l'appel. Un EPOLL, lui, garde ses inscriptions
//! (`epoll_ctl`) : chaque ÉLÉMENT (l'`epitem` de Linux) a ses entrées dans
//! les files d'attente de son fichier, pour toujours (jusqu'à DEL ou à la
//! fermeture). Quand un fichier change, sa file est réveillée, et le rappel
//! de l'élément (le `ep_poll_callback`) le range dans la LISTE DES PRÊTS de
//! son epoll, puis réveille qui attend dans `epoll_wait`. `epoll_wait` n'a
//! donc à regarder que les prêts : il les resonde un à un (un prêt peut ne
//! plus l'être), rend leurs événements, et décide de leur suite :
//!   - EPOLLET (déclenché par front) : oublié, jusqu'au prochain réveil de
//!     sa file. Bun inscrit tout ainsi ; un eventfd réveille sa file à
//!     chaque écriture, même sans lecture entre deux (mesuré) ;
//!   - EPOLLONESHOT : désarmé (plus aucun événement) jusqu'à un MOD ;
//!   - sinon (par niveau) : remis au bout de la liste, pour être resondé au
//!     prochain `epoll_wait`, tant qu'il est prêt.
//!
//! Deux verrous, comme Linux. Les éléments sont sous un `Mutex` (qui dort,
//! le `mtx`) : on le tient en sondant et en copiant vers le programme. La
//! liste des prêts est sous un `Verrou` (le `lock`) : le rappel la touche,
//! sous le verrou de la file du fichier, interruptions coupées. Ordre : le
//! Mutex d'un epoll, puis ceux des epolls qu'il surveille ; la file d'un
//! fichier, puis les prêts de l'epoll, puis ses deux files (`wq` pour
//! `epoll_wait`, `poll_wait` pour qui sonde l'epoll lui-même).
//!
//! Pendant un parcours des prêts (`epoll_wait`, le sondage de l'epoll), la
//! liste est mise de côté, et un rappel qui tombe entre-temps range son
//! élément dans une liste à part (l'`ovflist`), recousue à la fin : un
//! élément ET réveillé juste après avoir été sondé n'est pas perdu.
//!
//! La fermeture d'un fichier surveillé (son dernier `close`), sous le
//! verrou des fichiers : chaque élément qui le surveille (le fichier ouvert
//! les tient, le `f_ep` de Linux) est déclaré MOURANT et ses entrées
//! retirées des files ; son epoll l'oubliera sous son Mutex, à son prochain
//! passage (qu'on ne peut pas prendre sous un Verrou : il dort). Un
//! élément ne désigne son fichier que par le numéro de sa case dans la
//! table des fichiers ouverts, qu'un autre fichier pourra reprendre : il
//! ne le suit donc que sous le verrou des fichiers, et seulement s'il n'est
//! pas mourant : le marquage se fait sous ce même verrou, ou, pour un
//! élément retiré (DEL, ou le dernier close de son epoll), avant qu'il ne
//! le suive plus jamais (`retirer`, sous le Mutex de son epoll). C'est le rôle
//! qu'a chez Linux l'`eventpoll_release_file` qui précède la libération de
//! la `struct file`.

use crate::appels_fichiers::{FichierTenu, installer_fichier_puis, tenir, tenir_ouvert};
use crate::attente::{self, EntreeAttente, FileAttente, Mutex, Rappel, Sommeil};
use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur, dans_les_bornes};
use crate::descripteurs::{Fichier, FichierOuvert, Ouverts, Prive, Sorte, Tenu};
use crate::partage::{Arc, Weak};
use crate::sondage::{self, Delai, Inscrire, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, Table};
use crate::tache::{self, Reveil};
use crate::verrou::Verrou;
use crate::faillible::{FileFaillible, VecFaillible};
use crate::{cpu, pages, signaux, temps, vfs};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use fichiers::montages::Objet;

const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EINTR: i64 = 4;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const ENOSPC: i64 = 28;
const ELOOP: i64 = 40;

const O_RDWR: u32 = 2;
const O_CLOEXEC: u64 = 0o2000000;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLLEXCLUSIVE: u32 = 1 << 28;
const EPOLLWAKEUP: u32 = 1 << 29;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;
/// Les bits qui ne sont pas des événements : sans aucun autre, l'élément
/// est désarmé (un ONESHOT qui a servi).
const EP_PRIVATE_BITS: u32 = EPOLLWAKEUP | EPOLLONESHOT | EPOLLET | EPOLLEXCLUSIVE;
/// Ce qu'une inscription EPOLLEXCLUSIVE peut demander de plus
/// (EPOLLEXCLUSIVE_OK_BITS) : EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP,
/// EPOLLWAKEUP, EPOLLET ; pas EPOLLRDNORM ni les autres (mesuré : EINVAL).
/// 6d les acceptait à tort.
const EXCLUSIVE_PERMIS: u32 = POLLIN | POLLOUT | POLLERR | POLLHUP | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;
/// Le plus d'étages d'epoll les uns dans les autres.
const EP_MAX_NESTS: u32 = 4;
/// Le plus d'événements qu'un epoll_wait peut demander (EP_MAX_EVENTS) :
/// INT_MAX / sizeof(struct epoll_event), qui fait 12 octets (tassée).
const EP_MAX_EVENTS: u64 = i32::MAX as u64 / 12;
/// Ce que coûte un élément chez Linux (EP_ITEM_COST : un `epitem` de 120
/// octets et un `eppoll_entry` de 64, sur x86_64) : de quoi borner leur
/// nombre comme lui (`max_user_watches`, 4 % de la mémoire ; mesuré sur
/// l'hôte : 2 723 862 pour 12 Gio).
const COUT_D_UN_ELEMENT: u64 = 184;

/// Les éléments d'epoll en tout (le compte `epoll_watches` de l'utilisateur
/// : nos programmes n'en ont qu'un).
static SURVEILLANCES: AtomicU64 = AtomicU64::new(0);

/// max_user_watches : 4 % de la mémoire, en éléments.
fn max_surveillances() -> u64 {
    ((pages::total() as u64 / 25) << 12) / COUT_D_UN_ELEMENT
}

/// Un epoll (l'`eventpoll` de Linux).
pub struct Epoll {
    /// Ses éléments, sous le Mutex (le `mtx`, et l'arbre `rbr` : une liste
    /// suffit à nos dizaines d'éléments).
    elements: Mutex<Vec<Arc<Element>>>,
    /// Les prêts (le `lock`).
    prets: Verrou<Prets>,
    /// Où attend `epoll_wait` (le `wq`).
    wq: FileAttente,
    /// Où attend qui sonde l'epoll lui-même (le `poll_wait`) : `poll`, ou
    /// l'élément d'un autre epoll qui le surveille.
    poll_wait: FileAttente,
    /// Son fichier ouvert : on y trouve les éléments qui le surveillent
    /// (pour compter les étages au-dessus de lui, `etages_dessus`).
    fichier: AtomicU32,
    /// La recherche de boucles (le `gen` et le `loop_check_depth`), sous
    /// `EMBOITEMENTS` : déjà vu à ce tour-ci, et ce qu'on y a trouvé.
    generation: AtomicU64,
    profondeur_vue: AtomicU32,
}

/// La liste des prêts.
///
/// Les éléments y sont des Arc, et chacun n'y est qu'une fois (`lie`,
/// `deborde`) : leur place est réservée à l'inscription (chaque liste a la
/// capacité de tous les éléments), et le rappel n'alloue jamais. Un
/// élément n'y est donc jamais sans être aussi parmi les éléments
/// (`Epoll::verrouiller` retire les mourants des deux).
struct Prets {
    /// Les prêts (le `rdllist`).
    liste: VecDeque<Arc<Element>>,
    /// Ceux du parcours en cours (la `txlist`), retirés au fur et à mesure.
    parcourus: VecDeque<Arc<Element>>,
    /// Un parcours est en cours : les réveils vont dans `debordement` (l'`ovflist`).
    en_parcours: bool,
    debordement: Vec<Arc<Element>>,
}

/// Une entrée d'élément dans la file d'un fichier (l'`eppoll_entry` de
/// Linux). Un fichier en a deux au plus (un tube : sa file de lecteurs et
/// celle d'écrivains) : l'élément les porte, sans allocation.
struct EntreeElement {
    entree: EntreeAttente,
    /// La file où elle est inscrite (le `whead`).
    file: AtomicPtr<FileAttente>,
    /// Son élément (le `base`).
    element: AtomicPtr<Element>,
}

/// Un élément d'epoll (l'`epitem` de Linux) : le couple (fichier ouvert,
/// numéro de descripteur) qui l'identifie (mesuré : après un dup puis la
/// fermeture du premier numéro, l'inscription reste, au nom du premier),
/// ses événements, sa donnée, et ses entrées.
pub struct Element {
    /// Lui-même, pour se ranger dans les listes depuis son rappel.
    moi: Weak<Element>,
    epoll: Weak<Epoll>,
    fichier: Fichier,
    fd: u32,
    /// Les événements demandés (et EP_PRIVATE_BITS), écrits sous le Mutex,
    /// lus aussi par le rappel.
    evenements: AtomicU32,
    donnee: AtomicU64,
    /// Dans `liste` ou `parcourus` (le `ep_is_linked` de Linux), sous `prets`.
    lie: AtomicBool,
    /// Dans `debordement` (`next != EP_UNACTIVE_PTR`), sous `prets`.
    deborde: AtomicBool,
    /// Son fichier est fermé, ou il a été retiré : plus rien ne le touche.
    mourant: AtomicBool,
    entrees: [EntreeElement; 2],
    inscrites: AtomicUsize,
}

impl Epoll {
    fn new() -> Epoll {
        Epoll {
            elements: Mutex::new(Vec::new()),
            prets: Verrou::new(Prets { liste: VecDeque::new(), parcourus: VecDeque::new(), en_parcours: false, debordement: Vec::new() }),
            wq: FileAttente::new(),
            poll_wait: FileAttente::new(),
            fichier: AtomicU32::new(u32::MAX),
            generation: AtomicU64::new(0),
            profondeur_vue: AtomicU32::new(0),
        }
    }

    /// Le Mutex des éléments, et les mourants oubliés au passage : des
    /// éléments, et des prêts, où un élément mort par la fermeture de son
    /// fichier (`mourir`, sous le verrou des fichiers, qui ne peut pas
    /// prendre le Mutex) est peut-être encore lié. Il faut l'en retirer en
    /// même temps : la place des prêts n'est réservée que pour les éléments
    /// (`inserer`), et un rappel qui trouverait la liste pleine devrait
    /// allouer. Le Mutex tenu, aucun parcours n'est en cours : seule
    /// `liste` peut le tenir.
    fn verrouiller(&self) -> attente::GardeMutex<'_, Vec<Arc<Element>>> {
        let mut e = self.elements.verrouiller();
        if e.iter().any(|x| x.mourant.load(Relaxed)) {
            self.prets.verrouiller().liste.retain(|x| {
                let mourant = x.mourant.load(Relaxed);
                if mourant {
                    x.lie.store(false, Relaxed);
                }
                !mourant
            });
            e.retain(|x| !x.mourant.load(Relaxed));
        }
        e
    }

    /// Des événements attendent-ils (`ep_events_available`) ?
    fn disponible(p: &Prets) -> bool {
        !p.liste.is_empty() || p.en_parcours
    }

    /// Le début d'un parcours (`ep_start_scan`) : la liste mise de côté.
    fn debut_du_parcours(&self) {
        let mut p = self.prets.verrouiller();
        let p = &mut *p;
        core::mem::swap(&mut p.liste, &mut p.parcourus);
        p.en_parcours = true;
    }

    /// Le prochain élément du parcours, retiré.
    fn prochain(&self) -> Option<Arc<Element>> {
        self.prets.verrouiller().parcourus.pop_front()
    }

    /// Remet `e`, encore lié, en tête du parcours (il reviendra en tête des
    /// prêts).
    fn remettre(&self, e: Arc<Element>) {
        self.prets.verrouiller().parcourus.ajouter_devant_dans_la_place(e);
    }

    /// La fin d'un parcours (`ep_done_scan`) : dans l'ordre, ce qui reste du
    /// parcours, les réveils tombés pendant lui (dans leur ordre d'arrivée),
    /// puis les éléments remis par lui (par niveau) ; s'il reste des prêts,
    /// un `epoll_wait` est réveillé.
    fn fin_du_parcours(&self) {
        let mut p = self.prets.verrouiller();
        let p = &mut *p;
        for e in p.debordement.drain(..) {
            e.deborde.store(false, Relaxed);
            if !e.lie.swap(true, Relaxed) {
                p.parcourus.ajouter_derriere_dans_la_place(e);
            }
        }
        p.en_parcours = false;
        p.parcourus.deplacer_dans_la_place(&mut p.liste);
        core::mem::swap(&mut p.liste, &mut p.parcourus);
        if !p.liste.is_empty() && self.wq.active() {
            self.wq.reveiller(0, 1);
        }
    }

    /// Range `e` parmi les prêts s'il n'y est pas, et réveille qui attend
    /// (la fin d'`ep_insert` et d'`ep_modify`).
    fn ranger(&self, e: &Arc<Element>) {
        let pwake = {
            let mut p = self.prets.verrouiller();
            if e.lie.swap(true, Relaxed) {
                return;
            }
            p.liste.ajouter_derriere_dans_la_place(e.clone());
            if self.wq.active() {
                self.wq.reveiller(0, 1);
            }
            self.poll_wait.active()
        };
        if pwake {
            self.poll_wait.reveiller(POLLIN, 1);
        }
    }

    /// Le sondage de l'epoll (`__ep_eventpoll_poll`) : prêt (POLLIN |
    /// POLLRDNORM) si l'un de ses prêts l'est vraiment, chacun resondé ; un
    /// prêt qui ne l'est plus (un eventfd lu depuis) quitte la liste.
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        table.attendre(&self.poll_wait, tenu);
        let _elements = self.verrouiller();
        self.debut_du_parcours();
        let mut res = 0;
        while let Some(e) = self.prochain() {
            if !e.mourant.load(Relaxed) && e.sonder(&mut Table::new(None)) != 0 {
                self.remettre(e);
                res = POLLIN | POLLRDNORM;
                break;
            }
            e.lie.store(false, Relaxed);
        }
        self.fin_du_parcours();
        res
    }

    /// Rend jusqu'à `max` événements à l'adresse `tampon` (`ep_send_events`)
    /// : chaque prêt décroché, resondé (rien : oublié), copié ; puis désarmé
    /// (ONESHOT), oublié (ET) ou remis au bout (par niveau). Une copie qui
    /// échoue remet l'élément ; EFAULT si rien n'a été rendu. (Linux
    /// s'arrête d'abord sur un signal fatal ; chez nous, le programme meurt
    /// au retour, ce qu'il a reçu ne se voit pas.)
    fn envoyer(&self, tampon: u64, max: u64) -> i64 {
        let _elements = self.verrouiller();
        self.debut_du_parcours();
        let mut rendus = 0u64;
        let mut r = 0;
        while rendus < max {
            let Some(e) = self.prochain() else { break };
            e.lie.store(false, Relaxed);
            if e.mourant.load(Relaxed) {
                continue;
            }
            let revents = e.sonder(&mut Table::new(None));
            if revents == 0 {
                continue;
            }
            let mut o = [0u8; 12];
            o[..4].copy_from_slice(&revents.to_le_bytes());
            o[4..].copy_from_slice(&e.donnee.load(Relaxed).to_le_bytes());
            if copier_vers_utilisateur(tampon + rendus * 12, &o).is_err() {
                e.lie.store(true, Relaxed);
                self.remettre(e);
                if rendus == 0 {
                    r = -EFAULT;
                }
                break;
            }
            rendus += 1;
            let ev = e.evenements.load(Relaxed);
            if ev & EPOLLONESHOT != 0 {
                e.evenements.store(ev & EP_PRIVATE_BITS, Relaxed);
            } else if ev & EPOLLET == 0 {
                // Par niveau : remis au bout. Pendant le parcours, personne
                // d'autre ne range dans `liste` (les rappels débordent, les
                // epoll_ctl attendent le Mutex).
                e.lie.store(true, Relaxed);
                self.prets.verrouiller().liste.ajouter_derriere_dans_la_place(e);
            }
        }
        self.fin_du_parcours();
        if r < 0 { r } else { rendus as i64 }
    }

    /// L'attente d'`epoll_wait` (`ep_poll`) : des événements s'il y en a ;
    /// sinon dormir dans `wq` (exclusive, en tête : un réveil n'en réveille
    /// qu'une, la dernière arrivée), jusqu'au délai, un réveil, ou un signal
    /// (EINTR, jamais repris : mesuré, même avec SA_RESTART).
    fn attendre(&self, tampon: u64, max: u64, delai: Delai) -> i64 {
        let t = tache::courante();
        let mut fini = matches!(delai, Delai::Nul);
        let mut disponible = Self::disponible(&self.prets.verrouiller());
        loop {
            if disponible {
                let r = self.envoyer(tampon, max);
                if r != 0 {
                    return r;
                }
            }
            if fini {
                return 0;
            }
            if tache::signal_en_attente() {
                return -EINTR;
            }
            let interruptions = cpu::couper_interruptions();
            disponible = {
                let p = self.prets.verrouiller();
                let d = Self::disponible(&p);
                if !d {
                    self.wq.inscrire_exclusive_en_tete();
                }
                d
            };
            if !disponible {
                let echeance = match delai {
                    Delai::Jusqua(e) => Some(e),
                    Delai::Infini | Delai::Nul => None,
                };
                fini = attente::dormir(echeance, Sommeil::Interruptible) == Reveil::Echeance;
            }
            // Réveillée par la file, elle l'a quittée : il y a peut-être des
            // événements. Encore dedans : son échéance (rien, sauf un réveil
            // arrivé juste après), ou un signal.
            disponible = true;
            if self.wq.contient(t) {
                if fini {
                    disponible = false;
                }
                self.wq.retirer(t);
            }
            if interruptions {
                cpu::activer_interruptions();
            }
        }
    }

    /// Le dernier `close` de l'epoll (`ep_clear_and_put`), sous le verrou des
    /// fichiers : qui le sonde est réveillé ; chaque élément quitte son
    /// fichier et ses files. Personne ne tient plus le Mutex : on ne le prend
    /// que pour un fichier tenu (epoll_ctl, epoll_wait, un sondage), et c'est
    /// la dernière référence.
    fn liberer(&self, ouverts: &mut Ouverts) {
        if self.poll_wait.active() {
            self.poll_wait.reveiller(POLLIN, 1);
        }
        let mut elements = self.elements.essayer().expect("le Mutex d'un epoll ferme est pris");
        for e in elements.drain(..) {
            if !e.mourant.swap(true, Relaxed) {
                if let Some(f) = ouverts.peut_etre(e.fichier) {
                    f.surveillants.retain(|x| !Arc::ptr_eq(x, &e));
                }
                e.desinscrire();
                SURVEILLANCES.fetch_sub(1, Relaxed);
            }
        }
        let mut p = self.prets.verrouiller();
        p.liste.clear();
        p.parcourus.clear();
        p.debordement.clear();
    }
}

impl Element {
    /// Le fichier qu'il surveille, tenu, s'il n'est pas mourant (l'`epi_fget`
    /// de Linux) : sous le verrou des fichiers, sous lequel meurt l'élément
    /// d'un fichier fermé, sa case désigne encore son fichier ; un élément
    /// retiré meurt sous le Mutex de son epoll, que tient qui le sonde.
    fn tenir(&self) -> Option<FichierTenu> {
        vfs::avec_systeme(|s, _| (!self.mourant.load(Relaxed)).then(|| tenir_ouvert(s, self.fichier)))
    }

    /// Son sondage (`ep_item_poll`) : ce que dit son fichier, réduit à ce
    /// qu'il demande ; rien si son fichier n'est plus là.
    fn sonder(&self, table: &mut Table) -> u32 {
        let Some(tenu) = self.tenir() else { return 0 };
        let ev = self.evenements.load(Relaxed);
        table.changer_cle(ev);
        sondage::sonder(&tenu, table) & ev
    }

    /// Ses entrées retirées des files (`ep_unregister_pollwait`).
    fn desinscrire(&self) {
        let n = self.inscrites.swap(0, Relaxed);
        for e in &self.entrees[..n] {
            let file = e.file.load(Relaxed);
            // SAFETY: la file vit tant que son fichier est ouvert, et une
            // entrée est retirée avant qu'il ne soit fermé (à DEL, ou à sa
            // fermeture, sous le verrou des fichiers).
            if let Some(f) = unsafe { file.as_ref() } {
                f.enlever(&e.entree);
            }
        }
    }

    /// Son fichier est fermé : il ne servira plus (`eventpoll_release_file`).
    fn mourir(&self) {
        if !self.mourant.swap(true, Relaxed) {
            self.desinscrire();
            SURVEILLANCES.fetch_sub(1, Relaxed);
        }
    }

    /// Le rappel (`ep_poll_callback`), sous le verrou de la file du fichier :
    /// rien si l'élément est désarmé, ou si la clé ne l'intéresse pas ;
    /// sinon il se range parmi les prêts (ou dans le débordement pendant un
    /// parcours), réveille un `epoll_wait`, puis, hors des prêts, qui sonde
    /// l'epoll. Rend « réveillé » pour une entrée exclusive seulement si le
    /// réveil la concerne (EPOLLIN pour qui attend EPOLLIN...), et toujours
    /// pour une ordinaire.
    fn reveil(&self, cle: u32) -> bool {
        let Some(ep) = self.epoll.upgrade() else { return false };
        let ev = self.evenements.load(Relaxed);
        let mut ewake = false;
        let mut pwake = false;
        if ev & !EP_PRIVATE_BITS != 0 && (cle == 0 || cle & ev != 0) {
            let mut p = ep.prets.verrouiller();
            if let Some(moi) = self.moi.upgrade() {
                if p.en_parcours {
                    if !self.deborde.swap(true, Relaxed) {
                        p.debordement.ajouter_dans_la_place(moi);
                    }
                } else if !self.lie.swap(true, Relaxed) {
                    p.liste.ajouter_derriere_dans_la_place(moi);
                }
            }
            if ep.wq.active() {
                if ev & EPOLLEXCLUSIVE != 0 {
                    ewake = match cle & (POLLIN | POLLOUT) {
                        POLLIN => ev & POLLIN != 0,
                        POLLOUT => ev & POLLOUT != 0,
                        0 => true,
                        _ => false,
                    };
                }
                ep.wq.reveiller(0, 1);
            }
            pwake = ep.poll_wait.active();
        }
        if pwake {
            ep.poll_wait.reveiller(POLLIN, 1);
        }
        ewake || ev & EPOLLEXCLUSIVE == 0
    }
}

impl Rappel for EntreeElement {
    fn rappel(&self, cle: u32) -> bool {
        // SAFETY: l'élément contient l'entrée, et vit tant qu'elle est
        // inscrite (il est retiré des files avant d'être rendu).
        let e = unsafe { &*self.element.load(Relaxed) };
        e.reveil(cle)
    }
}

/// L'inscription d'un élément dans les files de son fichier, pendant son
/// premier sondage (`ep_ptable_queue_proc`) : exclusive pour EPOLLEXCLUSIVE.
struct Inscription<'a> {
    element: &'a Element,
    echec: bool,
}

impl Inscrire for Inscription<'_> {
    fn inscrire(&mut self, file: &FileAttente, _tenu: &FichierTenu, _cle: u32) {
        let n = self.element.inscrites.load(Relaxed);
        let Some(e) = self.element.entrees.get(n) else {
            self.echec = true;
            return;
        };
        e.file.store(file as *const FileAttente as *mut FileAttente, Relaxed);
        let qui: *const dyn Rappel = e;
        let exclusive = self.element.evenements.load(Relaxed) & EPOLLEXCLUSIVE != 0;
        // SAFETY: l'entrée est dans l'élément, qui est dans un Arc (il ne
        // bouge pas) et n'est rendu qu'après `desinscrire`.
        unsafe { e.entree.preparer_rappel(qui, exclusive) };
        // SAFETY: comme ci-dessus.
        file.ajouter(unsafe { Pin::new_unchecked(&e.entree) });
        self.element.inscrites.store(n + 1, Relaxed);
    }
}

/// Réserve dans `d` la place de `n` éléments.
fn reserver<T>(d: &mut VecDeque<T>, n: usize) -> bool {
    n <= d.capacity() || d.try_reserve(n - d.len()).is_ok()
}

/// La recherche de boucles et d'étages, et les ajouts d'un epoll dans un
/// epoll : un seul à la fois (l'`epnested_mutex` de Linux), avec le numéro
/// du tour (`loop_check_gen`).
static EMBOITEMENTS: Mutex<u64> = Mutex::new(0);

/// Le nombre d'étages d'epoll sous `ep` (`ep_loop_check_proc`), ou
/// u32::MAX si l'on y retrouve `cible` (une boucle) ou trop d'étages. Sous
/// `EMBOITEMENTS` ; chaque epoll n'est parcouru qu'une fois par tour.
fn etages_dessous(ep: &Epoll, cible: &Epoll, profondeur: u32, tour: u64) -> u32 {
    if ep.generation.load(Relaxed) == tour {
        return ep.profondeur_vue.load(Relaxed);
    }
    let elements = ep.verrouiller();
    ep.generation.store(tour, Relaxed);
    let mut r = 0u32;
    for e in elements.iter() {
        let Some(tenu) = e.tenir() else { continue };
        if tenu.sorte != Sorte::Epoll {
            continue;
        }
        let dessous = tenu.epoll();
        r = if core::ptr::eq(dessous, cible) || profondeur > EP_MAX_NESTS {
            u32::MAX
        } else {
            r.max(etages_dessous(dessous, cible, profondeur + 1, tour).saturating_add(1))
        };
        if r > EP_MAX_NESTS {
            break;
        }
    }
    ep.profondeur_vue.store(r, Relaxed);
    r
}

/// Le nombre d'étages d'epoll au-dessus de `ep` (`ep_get_upwards_depth_proc`),
/// d'après les éléments qui surveillent son fichier, sous le verrou des
/// fichiers.
fn etages_dessus(ouverts: &mut Ouverts, ep: &Epoll, tour: u64) -> u32 {
    if ep.generation.load(Relaxed) == tour {
        return ep.profondeur_vue.load(Relaxed);
    }
    let mut dessus: Vec<Arc<Epoll>> = Vec::new();
    if let Some(f) = ouverts.peut_etre(Fichier::de(ep.fichier.load(Relaxed))) {
        for e in f.surveillants.iter().filter(|e| !e.mourant.load(Relaxed)) {
            if let Some(x) = e.epoll.upgrade() {
                let _ = dessus.ajouter(x);
            }
        }
    }
    let r = dessus.iter().map(|x| etages_dessus(ouverts, x, tour).saturating_add(1)).max().unwrap_or(0);
    ep.generation.store(tour, Relaxed);
    ep.profondeur_vue.store(r, Relaxed);
    r
}

/// Le dernier `close` d'un fichier ouvert, sous le verrou des fichiers : les
/// éléments qui le surveillent meurent (`eventpoll_release`) ; si c'est un
/// epoll, ses propres éléments quittent leurs fichiers
/// (`ep_eventpoll_release`).
pub fn fichier_ferme(ouverts: &mut Ouverts, ferme: &mut FichierOuvert) {
    for e in ferme.surveillants.drain(..) {
        e.mourir();
    }
    ferme.surveillants = Vec::new();
    if let Prive::Epoll(ep) = &ferme.prive {
        ep.liberer(ouverts);
    }
}

/// epoll_create1(drapeaux) : EPOLL_CLOEXEC seul (EINVAL sinon). F_GETFL
/// rendra O_RDWR (mesuré).
pub fn epoll_create1(drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & !O_CLOEXEC != 0 {
        return -EINVAL;
    }
    let Ok(ep) = Arc::new(Epoll::new()) else { return -ENOMEM };
    let mut f = FichierOuvert::new(Sorte::Epoll, Tenu::Noyau(Objet::Anonyme), true, true, O_RDWR, b"anon_inode:[eventpoll]");
    f.chemin = crate::evenements::nom_anonyme(b"anon_inode:[eventpoll]");
    f.prive = Prive::Epoll(ep.clone());
    installer_fichier_puis(f, drapeaux & O_CLOEXEC != 0, |fichier| ep.fichier.store(fichier.numero(), Relaxed))
}

/// epoll_create(taille) : l'ancien appel ; la taille ne sert plus, mais
/// doit être positive (EINVAL).
pub fn epoll_create(taille: u64) -> i64 {
    if taille as i32 <= 0 {
        return -EINVAL;
    }
    epoll_create1(0)
}

/// epoll_ctl(epoll, opération, fd, événement), dans l'ordre de Linux
/// (`sys_epoll_ctl` puis `do_epoll_ctl`) :
///   1. l'événement est lu, sauf pour EPOLL_CTL_DEL (EFAULT, avant même
///      de regarder les descripteurs, mesuré) ;
///   2. les deux descripteurs (EBADF ; un O_PATH n'en est pas un ici) ;
///   3. le fichier visé doit savoir dire « prêt » (EPERM : un fichier
///      ordinaire, un dossier, /dev/null...) ;
///   4. EPOLLWAKEUP est retiré (il faut CAP_BLOCK_SUSPEND) ;
///   5. le premier doit être un epoll, et pas le fichier visé (EINVAL) ;
///   6. EPOLLEXCLUSIVE : pas pour MOD, ni pour un epoll visé, ni avec
///      d'autres événements que ceux qu'il permet (EINVAL) ;
///   7. un epoll dans un epoll : pas de boucle, et pas plus de
///      EP_MAX_NESTS (4) étages d'epoll en tout, de ce qu'il y a sous
///      l'epoll ajouté à ce qu'il y a au-dessus de celui qui le reçoit
///      (`ep_loop_check`, ELOOP ; mesuré : le cinquième emboîtement d'une
///      chaîne est refusé) ;
///   8. l'opération : ADD (EEXIST s'il est déjà inscrit, sous ce numéro ;
///      ENOSPC au-delà de max_user_watches), DEL (ENOENT s'il ne l'est
///      pas), MOD (ENOENT ; EINVAL pour une inscription EPOLLEXCLUSIVE),
///      une autre (EINVAL). ADD et MOD ajoutent toujours EPOLLERR et
///      EPOLLHUP.
/// La « struct epoll_event » est tassée sur x86_64 : 4 octets
/// d'événements, puis 8 de donnée. Linux vérifie aussi que l'ajout ne crée
/// pas trop de chemins de réveil vers un même fichier (plus de 1000
/// epolls qui le surveillent directement, `reverse_path_check`) ; pas
/// nous, pas encore.
pub fn epoll_ctl(epfd: u64, operation: u64, fd: u64, evenement: u64) -> i64 {
    let operation = operation as u32 as u64;
    let a_un_evenement = operation != EPOLL_CTL_DEL;
    let mut lu = (0u32, 0u64);
    if a_un_evenement {
        let mut o = [0u8; 12];
        if copier_depuis_utilisateur(&mut o, evenement).is_err() {
            return -EFAULT;
        }
        lu = (u32::from_le_bytes(o[..4].try_into().unwrap_or([0; 4])), u64::from_le_bytes(o[4..].try_into().unwrap_or([0; 8])));
    }
    // Les deux fichiers, tenus jusqu'à la fin de l'appel (deux `fdget`).
    let (Ok(e), Ok(cible)) = (tenir(epfd), tenir(fd)) else {
        return -EBADF;
    };
    if e.sorte == Sorte::Chemin || cible.sorte == Sorte::Chemin {
        return -EBADF;
    }
    if !cible.sorte.sait_attendre() {
        return -EPERM;
    }
    if a_un_evenement {
        lu.0 &= !EPOLLWAKEUP;
    }
    if e.fichier() == cible.fichier() || e.sorte != Sorte::Epoll {
        return -EINVAL;
    }
    if a_un_evenement
        && lu.0 & EPOLLEXCLUSIVE != 0
        && (operation == EPOLL_CTL_MOD || (operation == EPOLL_CTL_ADD && (cible.sorte == Sorte::Epoll || lu.0 & !EXCLUSIVE_PERMIS != 0)))
    {
        return -EINVAL;
    }
    let ep = e.epoll();
    // Un epoll ajouté à un epoll : la recherche de boucles, puis l'ajout,
    // un seul à la fois.
    let mut emboitements = None;
    if operation == EPOLL_CTL_ADD && cible.sorte == Sorte::Epoll {
        let mut tour = EMBOITEMENTS.verrouiller();
        *tour += 1;
        let dessous = etages_dessous(cible.epoll(), ep, 0, *tour);
        if dessous > EP_MAX_NESTS {
            return -ELOOP;
        }
        *tour += 1;
        let t = *tour;
        let dessus = vfs::avec_systeme(|s, _| etages_dessus(&mut s.ouverts, ep, t));
        if dessous + 1 + dessus > EP_MAX_NESTS {
            return -ELOOP;
        }
        emboitements = Some(tour);
    }
    let mut elements = ep.verrouiller();
    let ici = elements.iter().position(|x| x.fichier == cible.fichier() && x.fd == fd as u32);
    let evenements = lu.0 | POLLERR | POLLHUP;
    let r = match (operation, ici) {
        (EPOLL_CTL_ADD, None) => inserer(ep, &mut elements, &e, &cible, fd as u32, evenements, lu.1),
        (EPOLL_CTL_ADD, Some(_)) => -EEXIST,
        (EPOLL_CTL_DEL, Some(i)) => {
            let x = elements.remove(i);
            retirer(ep, &x);
            0
        }
        (EPOLL_CTL_MOD, Some(i)) if elements[i].evenements.load(Relaxed) & EPOLLEXCLUSIVE != 0 => -EINVAL,
        (EPOLL_CTL_MOD, Some(i)) => {
            let x = elements[i].clone();
            x.evenements.store(evenements, Relaxed);
            x.donnee.store(lu.1, Relaxed);
            // Les nouveaux événements posés AVANT de sonder : un réveil qui
            // suit voit l'élément réarmé (`ep_modify`).
            if x.sonder(&mut Table::new(None)) != 0 {
                ep.ranger(&x);
            }
            0
        }
        (EPOLL_CTL_DEL | EPOLL_CTL_MOD, None) => -ENOENT,
        _ => -EINVAL,
    };
    drop(elements);
    drop(emboitements);
    r
}

/// L'ajout d'un élément (`ep_insert`) : sous max_user_watches (ENOSPC) ;
/// sa place réservée partout (ENOMEM) ; rangé dans son epoll et dans son
/// fichier ; puis sondé avec une table qui inscrit ses entrées dans les
/// files du fichier, et rangé parmi les prêts s'il l'est déjà.
fn inserer(ep: &Epoll, elements: &mut Vec<Arc<Element>>, e: &FichierTenu, cible: &FichierTenu, fd: u32, evenements: u32, donnee: u64)
           -> i64 {
    if SURVEILLANCES.load(Relaxed) >= max_surveillances() {
        return -ENOSPC;
    }
    let n = elements.len() + 1;
    let place = elements.try_reserve(1).is_ok() && {
        let mut p = ep.prets.verrouiller();
        let p = &mut *p;
        reserver(&mut p.liste, n) && reserver(&mut p.parcourus, n) && (n <= p.debordement.capacity() || p.debordement.try_reserve(n - p.debordement.len()).is_ok())
    };
    if !place {
        return -ENOMEM;
    }
    let Prive::Epoll(arc) = &e.prive else { unreachable!("un epoll sans objet") };
    let x = Arc::new_cyclic(|moi| Element {
        moi: moi.clone(),
        epoll: Arc::downgrade(arc),
        fichier: cible.fichier(),
        fd,
        evenements: AtomicU32::new(evenements),
        donnee: AtomicU64::new(donnee),
        lie: AtomicBool::new(false),
        deborde: AtomicBool::new(false),
        mourant: AtomicBool::new(false),
        entrees: [const { EntreeElement { entree: EntreeAttente::new(), file: AtomicPtr::new(core::ptr::null_mut()), element: AtomicPtr::new(core::ptr::null_mut()) } }; 2],
        inscrites: AtomicUsize::new(0),
    });
    let Ok(x) = x else { return -ENOMEM };
    for en in &x.entrees {
        en.element.store(Arc::as_ptr(&x) as *mut Element, Relaxed);
    }
    let attache = vfs::avec_systeme(|s, _| {
        let f = s.ouverts.fichier(cible.fichier());
        f.surveillants.ajouter(x.clone()).is_ok()
    });
    if !attache {
        return -ENOMEM;
    }
    SURVEILLANCES.fetch_add(1, Relaxed);
    // La place est prise au début (`elements` est à nous : le Mutex de
    // l'epoll est tenu).
    elements.ajouter_dans_la_place(x.clone());
    let mut inscription = Inscription { element: &x, echec: false };
    let revents = x.sonder(&mut Table::new(Some(&mut inscription as &mut dyn Inscrire)));
    if inscription.echec {
        elements.pop();
        retirer(ep, &x);
        return -ENOMEM;
    }
    if revents != 0 {
        ep.ranger(&x);
    }
    0
}

/// Le retrait d'un élément (`__ep_remove`), sous le Mutex de son epoll, son
/// fichier tenu par l'appelant : ses entrées, sa place dans son fichier et
/// parmi les prêts.
fn retirer(ep: &Epoll, x: &Arc<Element>) {
    if x.mourant.swap(true, Relaxed) {
        return;
    }
    x.desinscrire();
    vfs::avec_systeme(|s, _| {
        if let Some(f) = s.ouverts.peut_etre(x.fichier) {
            f.surveillants.retain(|y| !Arc::ptr_eq(y, x));
        }
    });
    let mut p = ep.prets.verrouiller();
    if x.lie.swap(false, Relaxed) {
        p.liste.retain(|y| !Arc::ptr_eq(y, x));
    }
    SURVEILLANCES.fetch_sub(1, Relaxed);
}

/// Les vérifications d'epoll_wait (`ep_check_params`, après `fdget`) : un
/// numéro fermé ou un O_PATH : EBADF ; maxevents nul, négatif, ou plus que
/// EP_MAX_EVENTS : EINVAL ; le tampon hors des adresses des programmes :
/// EFAULT, avant d'attendre (`access_ok` : dans les bornes mais pas projeté,
/// il ne se voit qu'à la copie) ; pas un epoll : EINVAL.
fn verifier(epfd: u64, tampon: u64, max: u64) -> Result<FichierTenu, i64> {
    let o = tenir(epfd)?;
    if o.sorte == Sorte::Chemin {
        return Err(-EBADF);
    }
    let max = max as i32;
    if max <= 0 || max as u64 > EP_MAX_EVENTS {
        return Err(-EINVAL);
    }
    if !dans_les_bornes(tampon, max as u64 * 12) {
        return Err(-EFAULT);
    }
    if o.sorte != Sorte::Epoll {
        return Err(-EINVAL);
    }
    Ok(o)
}

/// `do_epoll_wait`.
fn sys_epoll_wait(epfd: u64, tampon: u64, max: u64, delai: Delai) -> i64 {
    match verifier(epfd, tampon, max) {
        Ok(o) => o.epoll().attendre(tampon, max as i32 as u64, delai),
        Err(e) => e,
    }
}

/// Un délai en millisecondes (`ep_timeout_to_timespec`) : négatif, toujours.
fn delai_ms(ms: u64) -> Delai {
    let ms = ms as i32;
    if ms < 0 {
        return Delai::Infini;
    }
    if ms == 0 {
        return Delai::Nul;
    }
    Delai::Jusqua(temps::ns_monotone().saturating_add(ms as u64 * 1_000_000))
}

/// epoll_wait(epoll, tampon, maxevents, délai en ms).
pub fn epoll_wait(epfd: u64, tampon: u64, max: u64, ms: u64) -> i64 {
    sys_epoll_wait(epfd, tampon, max, delai_ms(ms))
}

/// `do_epoll_pwait` : le masque temporaire d'abord (EINVAL, EFAULT), puis
/// l'attente ; le masque rendu tout de suite, sauf interrompue (EINTR).
fn sys_epoll_pwait(epfd: u64, tampon: u64, max: u64, delai: Delai, masque: u64, taille: u64) -> i64 {
    if let Err(e) = signaux::masque_temporaire(masque, taille) {
        return e;
    }
    let r = sys_epoll_wait(epfd, tampon, max, delai);
    signaux::fin_du_masque_temporaire(r == -EINTR);
    r
}

/// epoll_pwait(epoll, tampon, maxevents, délai en ms, masque, taille).
pub fn epoll_pwait(epfd: u64, tampon: u64, max: u64, ms: u64, masque: u64, taille: u64) -> i64 {
    sys_epoll_pwait(epfd, tampon, max, delai_ms(ms), masque, taille)
}

/// epoll_pwait2(epoll, tampon, maxevents, délai en timespec, masque,
/// taille) : le délai d'abord (EFAULT, EINVAL), comme ppoll ; nul : attendre
/// toujours. C'est ce qu'appelle Bun.
pub fn epoll_pwait2(epfd: u64, tampon: u64, max: u64, tsp: u64, masque: u64, taille: u64) -> i64 {
    let d = match sondage::delai_timespec(tsp) {
        Ok(d) => d,
        Err(e) => return e,
    };
    sys_epoll_pwait(epfd, tampon, max, d, masque, taille)
}
