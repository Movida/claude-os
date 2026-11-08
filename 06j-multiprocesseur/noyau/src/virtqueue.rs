//! Les files de virtio (« virtqueues »), au format « split » de la
//! spécification 1.2 (section 2.7).
//!
//! Une file est un échange de TAMPONS entre le pilote et le périphérique,
//! par trois tableaux en mémoire ordinaire, que les deux lisent et écrivent
//! (le périphérique par DMA) :
//!   - la TABLE DES DESCRIPTEURS : chaque descripteur désigne un tampon
//!     (adresse physique, longueur), dit si le périphérique doit le lire ou
//!     l'écrire, et peut se chaîner au suivant (un paquet en deux morceaux) ;
//!   - l'anneau « AVAIL » (écrit par le pilote) : les têtes de chaînes que
//!     le pilote confie au périphérique, et un index qui ne fait qu'avancer ;
//!   - l'anneau « USED » (écrit par le périphérique) : les têtes qu'il
//!     rend, avec le nombre d'octets qu'il y a écrits, et son propre index.
//! Le pilote prévient le périphérique qu'avail a avancé par une NOTIFICATION
//! (une écriture dans la zone de notification, virtio.rs) ; le périphérique
//! prévient le pilote qu'used a avancé par une INTERRUPTION (ici une
//! MSI-X). Pour une carte réseau : dans la file de réception, des tampons
//! vides que la carte remplit de trames reçues ; dans celle d'émission, des
//! trames à envoyer, que la carte rend une fois parties.
//!
//! EVENT_IDX (la fonctionnalité VIRTIO_RING_F_EVENT_IDX, négociée comme le
//! fait Linux) : au lieu d'un simple drapeau « ne m'interromps pas »,
//! chaque côté écrit, à la fin de l'anneau de l'autre, l'index à partir
//! duquel il veut être prévenu (`used_event` à la fin d'avail, pour les
//! interruptions ; `avail_event` à la fin d'used, pour les notifications).
//! Le périphérique n'interrompt qu'en franchissant `used_event`, le pilote
//! ne notifie qu'en franchissant `avail_event` (la formule
//! `vring_need_event`) : une rafale de paquets coûte une interruption, pas
//! une par paquet.
//!
//! LES BARRIÈRES. Le périphérique tourne en même temps que nous (un autre
//! fil de QEMU, ou le matériel) : l'ordre des écritures en mémoire compte.
//! On écrit le descripteur, puis son entrée dans avail, puis l'index
//! d'avail ; on lit l'index d'used, puis ses entrées. Sur x86, la mémoire
//! garde l'ordre des écritures entre elles et des lectures entre elles
//! (« TSO ») : une barrière du COMPILATEUR suffit (le `virtio_wmb` et le
//! `virtio_rmb` de Linux, qui valent `barrier()` sur x86). Mais une lecture
//! peut passer avant une écriture plus ancienne : entre « écrire l'index »
//! et « lire l'index d'événement de l'autre », il faut une vraie barrière
//! (`mfence`, le `virtio_mb` de Linux), sinon une notification ou une
//! interruption se perd.
//!
//! La mémoire : la table des descripteurs dans une page, les deux anneaux
//! dans une autre (avail au début, used à 4 octets près après lui), prises
//! au buddy : contiguës, leur adresse physique suffit au périphérique (pas
//! d'IOMMU). 256 entrées au plus (16 octets par descripteur : une page).
//! Le pilote ne garde, par tête de chaîne, qu'un JETON (un nombre à lui :
//! l'indice de son tampon) qu'`obtenir` lui rend.

use crate::espace;
use crate::pages;
use core::sync::atomic::{Ordering, compiler_fence, fence};

/// Le nombre maximal d'entrées d'une file (une page de descripteurs).
pub const TAILLE_MAX: u16 = 256;

/// Dans un descripteur : la chaîne continue au descripteur `suivant`.
const SUIVANT: u16 = 1;
/// Dans un descripteur : le périphérique ÉCRIT dans ce tampon (sinon il le
/// lit).
pub const ECRIT_PAR_PERIPHERIQUE: u16 = 2;
/// Dans les drapeaux d'avail : ne pas interrompre (sans EVENT_IDX).
const SANS_INTERRUPTION: u16 = 1;

/// Un tampon d'une chaîne : adresse physique, longueur, drapeaux.
#[derive(Clone, Copy)]
pub struct Tampon {
    pub physique: u64,
    pub longueur: u32,
    pub drapeaux: u16,
}

/// Une file : ses tableaux, et l'état du pilote.
pub struct Virtqueue {
    taille: u16,
    /// Les pages, par leur adresse physique (rendues par Drop).
    page_descripteurs: u64,
    page_anneaux: u64,
    /// Les adresses virtuelles des trois tableaux.
    descripteurs: u64,
    avail: u64,
    used: u64,
    /// Le premier descripteur libre (chaînés par leur champ `next`), et leur
    /// nombre.
    premier_libre: u16,
    libres: u16,
    /// L'index d'avail tel que nous l'avons écrit, et celui d'used jusqu'où
    /// nous avons lu.
    avail_index: u16,
    used_lu: u16,
    /// Les entrées ajoutées depuis la dernière notification.
    ajoutees: u16,
    /// EVENT_IDX négocié.
    evenements: bool,
    /// Les interruptions sont-elles coupées (par nous) ?
    coupees: bool,
    /// Le jeton de chaque tête de chaîne en cours (None : libre).
    jetons: [Option<u32>; TAILLE_MAX as usize],
}

// La disposition des tableaux (spécification 2.7.5 à 2.7.8).
const TAILLE_DESCRIPTEUR: u64 = 16;
fn taille_avail(n: u16) -> u64 {
    // flags, idx, ring[n], used_event
    4 + 2 * n as u64 + 2
}

impl Virtqueue {
    /// Une file de `taille` entrées (une puissance de 2, au plus 256), aux
    /// tableaux vides. None : plus de mémoire.
    pub fn new(taille: u16, evenements: bool) -> Option<Virtqueue> {
        debug_assert!(taille.is_power_of_two() && taille <= TAILLE_MAX);
        let page_descripteurs = pages::allouer(0)?;
        let Some(page_anneaux) = pages::allouer(0) else {
            pages::liberer(page_descripteurs, 0);
            return None;
        };
        let descripteurs = espace::virtuelle(page_descripteurs);
        let avail = espace::virtuelle(page_anneaux);
        // used aligné sur 4 (spécification 2.7 : 4 pour l'anneau used).
        let used = avail + taille_avail(taille).next_multiple_of(4);
        // SAFETY: deux pages qui viennent d'être données, à nous, vues par
        // la projection directe.
        unsafe {
            core::ptr::write_bytes(descripteurs as *mut u8, 0, 4096);
            core::ptr::write_bytes(avail as *mut u8, 0, 4096);
        }
        let mut q = Virtqueue {
            taille, page_descripteurs, page_anneaux, descripteurs, avail, used,
            premier_libre: 0, libres: taille, avail_index: 0, used_lu: 0, ajoutees: 0, evenements,
            coupees: false, jetons: [None; TAILLE_MAX as usize],
        };
        // Les descripteurs libres, chaînés dans l'ordre.
        for i in 0..taille {
            q.ecrire_descripteur(i, 0, 0, 0, (i + 1) % taille);
        }
        Some(q)
    }

    /// Les adresses physiques des trois tableaux, à donner au périphérique.
    pub fn adresses(&self) -> (u64, u64, u64) {
        (self.page_descripteurs, self.page_anneaux, espace::physique(self.used))
    }

    pub fn taille(&self) -> u16 {
        self.taille
    }

    /// Le nombre de descripteurs libres.
    pub fn libres(&self) -> u16 {
        self.libres
    }

    fn ecrire_descripteur(&mut self, i: u16, physique: u64, longueur: u32, drapeaux: u16, suivant: u16) {
        let d = self.descripteurs + i as u64 * TAILLE_DESCRIPTEUR;
        // SAFETY: `i` < taille : un descripteur de notre page.
        unsafe {
            (d as *mut u64).write_volatile(physique);
            ((d + 8) as *mut u32).write_volatile(longueur);
            ((d + 12) as *mut u16).write_volatile(drapeaux);
            ((d + 14) as *mut u16).write_volatile(suivant);
        }
    }

    fn suivant_du_descripteur(&self, i: u16) -> (u16, u16) {
        let d = self.descripteurs + i as u64 * TAILLE_DESCRIPTEUR;
        // SAFETY: comme ecrire_descripteur.
        unsafe { (((d + 12) as *const u16).read_volatile(), ((d + 14) as *const u16).read_volatile()) }
    }

    fn mot16(adresse: u64) -> u16 {
        // SAFETY: une adresse de nos anneaux (les appelants la calculent
        // dans leurs bornes).
        unsafe { (adresse as *const u16).read_volatile() }
    }

    fn ecrire16(adresse: u64, valeur: u16) {
        // SAFETY: comme mot16.
        unsafe { (adresse as *mut u16).write_volatile(valeur) }
    }

    /// Confie au périphérique la chaîne des tampons `tampons` (1 à
    /// `libres()`), avec le jeton `jeton`, rendu par `obtenir`. false : pas
    /// assez de descripteurs libres.
    pub fn ajouter(&mut self, tampons: &[Tampon], jeton: u32) -> bool {
        let n = tampons.len() as u16;
        if n == 0 || n > self.libres {
            return false;
        }
        let tete = self.premier_libre;
        let mut i = tete;
        for (k, t) in tampons.iter().enumerate() {
            let (_, suivant_libre) = self.suivant_du_descripteur(i);
            let dernier = k + 1 == tampons.len();
            let drapeaux = t.drapeaux | if dernier { 0 } else { SUIVANT };
            self.ecrire_descripteur(i, t.physique, t.longueur, drapeaux, if dernier { 0 } else { suivant_libre });
            if dernier {
                self.premier_libre = suivant_libre;
            }
            i = suivant_libre;
        }
        self.libres -= n;
        self.jetons[tete as usize] = Some(jeton);
        // L'entrée d'avail, puis (après une barrière : le descripteur et
        // l'entrée sont en mémoire avant que l'index ne les montre) l'index.
        let place = self.avail_index % self.taille;
        Self::ecrire16(self.avail + 4 + 2 * place as u64, tete);
        compiler_fence(Ordering::Release);
        self.avail_index = self.avail_index.wrapping_add(1);
        Self::ecrire16(self.avail + 2, self.avail_index);
        self.ajoutees = self.ajoutees.wrapping_add(1);
        true
    }

    /// Faut-il notifier le périphérique de ce qui a été ajouté depuis la
    /// dernière fois (le `virtqueue_kick_prepare_split` de Linux) ?
    pub fn faut_il_notifier(&mut self) -> bool {
        // L'index d'avail est écrit avant que l'on lise ce que veut le
        // périphérique : une vraie barrière (une lecture passerait sinon
        // avant l'écriture).
        fence(Ordering::SeqCst);
        let nouveau = self.avail_index;
        let ancien = nouveau.wrapping_sub(self.ajoutees);
        self.ajoutees = 0;
        if self.evenements {
            // avail_event, à la fin de l'anneau used.
            let evenement = Self::mot16(self.used + 4 + 8 * self.taille as u64);
            besoin(evenement, nouveau, ancien)
        } else {
            // VRING_USED_F_NO_NOTIFY : le bit 0 des drapeaux d'used.
            Self::mot16(self.used) & 1 == 0
        }
    }

    /// Le prochain tampon rendu par le périphérique : son jeton, et le
    /// nombre d'octets qu'il y a écrits. None : rien de neuf. Un périphérique
    /// qui rend une tête impossible (hors de la table, ou qui n'est pas en
    /// cours) est ignoré, et dit : la file est alors fausse (Linux la marque
    /// « cassée »).
    pub fn obtenir(&mut self) -> Option<(u32, u32)> {
        loop {
            let index_used = Self::mot16(self.used + 2);
            if index_used == self.used_lu {
                return None;
            }
            // L'index lu avant les entrées qu'il montre.
            compiler_fence(Ordering::Acquire);
            let place = self.used_lu % self.taille;
            let entree = self.used + 4 + 8 * place as u64;
            // SAFETY: une entrée de notre anneau used.
            let (id, longueur) = unsafe { ((entree as *const u32).read_volatile(), ((entree + 4) as *const u32).read_volatile()) };
            self.used_lu = self.used_lu.wrapping_add(1);
            if !self.coupees && self.evenements {
                // used_event : être prévenu dès la prochaine entrée.
                Self::ecrire16(self.avail + 4 + 2 * self.taille as u64, self.used_lu);
                fence(Ordering::SeqCst);
            }
            let Some(jeton) = (id < self.taille as u32).then(|| self.jetons[id as usize].take()).flatten() else {
                afficherln!("[virtio] file : le peripherique rend le descripteur {} qui n'est pas a lui", id);
                continue;
            };
            self.rendre_chaine(id as u16);
            return Some((jeton, longueur));
        }
    }

    /// Remet la chaîne de tête `tete` dans les libres.
    fn rendre_chaine(&mut self, tete: u16) {
        let mut i = tete;
        let mut n = 1;
        loop {
            let (drapeaux, suivant) = self.suivant_du_descripteur(i);
            if drapeaux & SUIVANT == 0 || n >= self.taille {
                break;
            }
            i = suivant % self.taille;
            n += 1;
        }
        // Le dernier de la chaîne pointe vers l'ancien premier libre.
        let d = self.descripteurs + i as u64 * TAILLE_DESCRIPTEUR;
        Self::ecrire16(d + 14, self.premier_libre);
        Self::ecrire16(d + 12, 0);
        self.premier_libre = tete;
        self.libres += n;
    }

    /// Coupe les interruptions de cette file (le `virtqueue_disable_cb` de
    /// Linux) : le travail continue par `obtenir`, jusqu'à `rallumer`.
    pub fn couper(&mut self) {
        if !self.coupees {
            self.coupees = true;
            if self.evenements {
                // Un `used_event` loin derrière : Linux écrit 0 (« a hack »,
                // dit-il), que l'index used refranchit tous les 65 536
                // tampons ; nous, l'index le plus éloigné de l'index courant
                // (used_lu − 0x8000), que la formule, qui compare des
                // écarts de 16 bits, ne franchit qu'après 32 768 tampons
                // traités sans rallumer.
                Self::ecrire16(self.avail + 4 + 2 * self.taille as u64, self.used_lu.wrapping_sub(0x8000));
            } else {
                Self::ecrire16(self.avail, SANS_INTERRUPTION);
            }
        }
    }

    /// Rallume les interruptions, puis dit s'il y a déjà du travail (le
    /// `virtqueue_enable_cb` de Linux : true, il n'y a rien, on peut dormir
    /// ; false, des entrées sont arrivées entre-temps, à traiter sans
    /// attendre d'interruption).
    pub fn rallumer(&mut self) -> bool {
        self.coupees = false;
        if self.evenements {
            Self::ecrire16(self.avail + 4 + 2 * self.taille as u64, self.used_lu);
        } else {
            Self::ecrire16(self.avail, 0);
        }
        // Notre écriture avant la lecture de l'index du périphérique.
        fence(Ordering::SeqCst);
        Self::mot16(self.used + 2) == self.used_lu
    }
}

/// La formule de virtio (`vring_need_event`) : le périphérique a demandé à
/// être prévenu à l'index `evenement` ; l'index est passé de `ancien` à
/// `nouveau` ; l'a-t-il franchi ? En arithmétique de 16 bits.
fn besoin(evenement: u16, nouveau: u16, ancien: u16) -> bool {
    nouveau.wrapping_sub(evenement).wrapping_sub(1) < nouveau.wrapping_sub(ancien)
}

impl Drop for Virtqueue {
    /// Les pages rendues : le périphérique doit déjà avoir été remis à zéro
    /// (il n'y touche plus).
    fn drop(&mut self) {
        pages::liberer(self.page_descripteurs, 0);
        pages::liberer(self.page_anneaux, 0);
    }
}
