//! Les paquets : une trame et ses en-têtes, dans un tampon du noyau (le
//! `sk_buff` de Linux).
//!
//! Un paquet traverse les étages de la pile sans être recopié : à
//! l'émission, chaque étage AJOUTE son en-tête devant (UDP, puis IP, puis
//! Ethernet), dans une MARGE laissée libre en tête du tampon (le
//! `skb_reserve` de Linux) ; à la réception, chaque étage RETIRE le sien
//! (le `skb_pull`) et passe le reste au suivant. Le tampon, et ses bornes
//! (début et fin des données).
//!
//! Tout ce qui le fabrique peut échouer sans paniquer : une trame reçue du
//! dehors, une rafale qui épuise la mémoire, ne doivent jamais arrêter le
//! noyau (`try_reserve`). Les bornes sont vérifiées à chaque ajout et à
//! chaque retrait : un en-tête plus long que ce qui reste est une erreur,
//! jamais une lecture hors du tampon.
//!
//! Les octets de tous les paquets vivants sont comptés (`vivants`) : le
//! lanceur les montre quand « memoire rendue » échoue, pour qu'un écart
//! dise tout de suite s'il vient d'une file du réseau.

use crate::attente::FileAttente;
use crate::faillible;
use crate::partage::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// Les octets des tampons de tous les paquets vivants.
static VIVANTS: AtomicUsize = AtomicUsize::new(0);

/// Les octets des tampons de tous les paquets vivants.
pub fn vivants() -> usize {
    VIVANTS.load(Ordering::Relaxed)
}

/// La marge laissée devant les données d'un paquet à émettre : de quoi
/// ajouter les en-têtes d'UDP (8 octets), d'IPv4 (20 à 60) et d'Ethernet
/// (14) sans recopier.
pub const MARGE: usize = 96;

/// Ce que Linux ajoute à la taille des données pour la « taille vraie »
/// d'un paquet, celle que comptent ses files (celle des voisins, celles des
/// sockets) : son `sk_buff` (256 octets) et sa `skb_shared_info` (320).
pub const SURCOUT: usize = 576;

/// Ce qu'une socket a encore dans les files d'en bas (la file de la carte, celle des
/// voisins) : le `sk_wmem_alloc` de Linux et ses TSQ_THROTTLED, partagés avec ses
/// paquets (inet::tcp::carte dit à quoi ils servent). Un `Arc` à part, plutôt que le
/// paquet qui tiendrait la socket elle-même comme chez Linux : notre partie de la socket
/// (la `Possession`) ne connaît pas son `Arc<Socket>`, et un paquet encore dans la carte
/// ne doit pas faire durer toute une socket fermée.
pub struct Retenue {
    octets: AtomicUsize,
    etranglee: AtomicBool,
    /// La fin d'émission est venue pour une socket étranglée : à pousser.
    a_pousser: AtomicBool,
    /// Le plus grand numéro d'envoi que la carte ait fini.
    rendu: AtomicU64,
    /// Le numéro de la socket, pour la rappeler.
    socket: u64,
    /// Pour une socket de datagrammes (UDP, ping : les soldes d'avant 6k), sa file d'attente :
    /// une place rendue quand quelqu'un y attend (un envoi, poll, epoll) la fait rappeler
    /// (`sock_wfree` et `sk_write_space`, voir `Proprietaire::rendre`) ; et sa limite,
    /// SO_SNDBUF (le `sk_sndbuf`, une copie de celui de la socket, que la fin d'émission lit
    /// sans elle).
    attente: Option<Arc<FileAttente>>,
    limite: AtomicUsize,
    /// La place a manqué à un envoi, ou à `poll` (SOCKWQ_ASYNC_NOSPACE) : la place rendue
    /// le dira aussi par SIGIO (O_ASYNC).
    sans_place: AtomicBool,
}

impl Retenue {
    pub const fn new(socket: u64) -> Retenue {
        Retenue {
            octets: AtomicUsize::new(0), etranglee: AtomicBool::new(false), a_pousser: AtomicBool::new(false), rendu: AtomicU64::new(0),
            socket, attente: None, limite: AtomicUsize::new(0), sans_place: AtomicBool::new(false),
        }
    }

    /// Celle d'une socket de datagrammes de numéro `socket`, de file `attente`, et de
    /// SO_SNDBUF `limite`.
    pub fn pour_datagrammes(socket: u64, limite: usize, attente: Arc<FileAttente>) -> Retenue {
        Retenue { attente: Some(attente), limite: AtomicUsize::new(limite), ..Retenue::new(socket) }
    }

    /// SO_SNDBUF.
    pub fn limite(&self) -> usize {
        self.limite.load(Ordering::Relaxed)
    }

    /// SO_SNDBUF a changé.
    pub fn poser_limite(&self, limite: usize) {
        self.limite.store(limite, Ordering::Relaxed);
    }

    /// Un envoi a de la place : moins que SO_SNDBUF en route (`sock_alloc_send_pskb`).
    pub fn place(&self) -> bool {
        self.octets.load(Ordering::SeqCst) < self.limite.load(Ordering::Relaxed)
    }

    /// `poll` dit POLLOUT : moins que la moitié de SO_SNDBUF en route (`sock_writeable`).
    pub fn ecriture_possible(&self) -> bool {
        self.octets.load(Ordering::SeqCst) < self.limite.load(Ordering::Relaxed) / 2
    }

    /// La place a manqué (SOCKWQ_ASYNC_NOSPACE) ; `encore_sans_place` le revérifie
    /// après le drapeau (le motif de Dekker avec `Proprietaire::rendre`, voir
    /// `etrangler`) : la place rendue entre les deux, on se rappelle soi-même.
    pub fn marquer_sans_place(&self, encore_sans_place: impl FnOnce() -> bool) {
        self.sans_place.store(true, Ordering::SeqCst);
        if !encore_sans_place() && self.sans_place.swap(false, Ordering::SeqCst) {
            super::tache::armer_precis(self.socket, 0);
        }
    }

    /// Le rappel d'une socket de datagrammes est venu (la tâche du réseau) : le drapeau
    /// « sans place » effacé (asynchrone.rs garde le sien, pour SIGIO).
    pub fn rappelee(&self) {
        self.sans_place.store(false, Ordering::Relaxed);
    }

    pub fn octets(&self) -> usize {
        self.octets.load(Ordering::Relaxed)
    }

    pub fn rendu(&self) -> u64 {
        self.rendu.load(Ordering::Relaxed)
    }

    /// Le paquet de cet envoi ne partira jamais (pas de route, plus de mémoire).
    pub fn envoi_perdu(&self, numero: u64) {
        self.rendu.fetch_max(numero, Ordering::Relaxed);
    }

    /// TSQ_THROTTLED : rappeler la socket à la prochaine fin d'émission. Tout a pu
    /// être rendu avant ce drapeau : personne ne le verrait, on se rappelle soi-même.
    /// Le motif de Dekker (processeur.rs) avec `Proprietaire::rendre` : ici « je pose
    /// `etranglee`, puis je lis `octets` », là « je rends mes `octets`, puis je lis
    /// `etranglee` » ; sans SeqCst des deux côtés (un `xchg` pour l'écriture), x86
    /// laisse la lecture d'`octets` passer devant l'écriture encore dans le tampon :
    /// la socket voit encore des octets en vol, la fin d'émission ne voit pas le
    /// drapeau, personne ne rappelle la socket, et TCP attend un minuteur. C'est le
    /// `smp_mb__after_atomic()` de `tcp_small_queue_check` (« It is possible TX
    /// completion already happened before we set TSQ_THROTTLED »). Sur un seul
    /// processeur, invisible.
    pub fn etrangler(&self) {
        self.etranglee.store(true, Ordering::SeqCst);
        if self.octets.load(Ordering::SeqCst) == 0 && self.etranglee.swap(false, Ordering::SeqCst) {
            self.rappeler();
        }
    }

    /// La socket a-t-elle été rappelée ? Le drapeau reste : voir `pousse`.
    pub fn a_pousser(&self) -> bool {
        self.a_pousser.load(Ordering::Relaxed)
    }

    /// Le rappel a eu lieu : rend s'il y en avait un.
    pub fn pousse(&self) -> bool {
        self.a_pousser.swap(false, Ordering::Relaxed)
    }

    /// `tcp_wfree`, jusqu'à la file : une échéance tout de suite pour cette socket (la
    /// tâche du réseau la fera travailler, comme un minuteur).
    fn rappeler(&self) {
        self.a_pousser.store(true, Ordering::Relaxed);
        super::tache::armer_precis(self.socket, 0);
    }
}

/// Le lien d'un paquet à sa socket, jusqu'à ce que la carte l'ait fini (le `skb->sk`
/// et son destructeur).
pub struct Proprietaire {
    retenue: Arc<Retenue>,
    taille: usize,
    numero: u64,
}

impl Proprietaire {
    /// La carte a fini (`tcp_wfree`) ; ou le paquet n'attend pas (`skb_orphan`), ou il
    /// est jeté.
    pub fn rendre(self) {
        let r = &self.retenue;
        // SeqCst : la paire d'`etrangler` (voir là), et de `marquer_sans_place`.
        let reste = r.octets.fetch_sub(self.taille, Ordering::SeqCst) - self.taille;
        r.rendu.fetch_max(self.numero, Ordering::Relaxed);
        if r.etranglee.swap(false, Ordering::SeqCst) {
            r.rappeler();
        }
        // Une socket de datagrammes (`sock_wfree`, puis `sock_def_write_space`) : assez de
        // place pour un progrès « significatif » (moins de la moitié de SO_SNDBUF en route),
        // et quelqu'un attend dans sa file, ou a vu la place manquer. Le réveil lui-même dans
        // la tâche du réseau, comme `tcp_wfree` (`rappeler`) : nous sommes sous le verrou de
        // la carte, et SIGIO prend ceux des processus (asynchrone.rs).
        if let Some(a) = &r.attente
            && reste < r.limite.load(Ordering::Relaxed) / 2
            && (r.sans_place.load(Ordering::SeqCst) || a.active())
        {
            super::tache::armer_precis(r.socket, 0);
        }
    }
}

pub struct Paquet {
    tampon: Vec<u8>,
    debut: usize,
    fin: usize,
    proprietaire: Option<Proprietaire>,
}

impl Paquet {
    /// Un paquet vide, avec la marge pour ses en-têtes et la place pour
    /// `longueur` octets de données. None : plus de mémoire.
    pub fn vide(longueur: usize) -> Option<Paquet> {
        let tampon = faillible::remplie(MARGE + longueur, 0).ok()?;
        VIVANTS.fetch_add(tampon.capacity(), Ordering::Relaxed);
        Some(Paquet { tampon, debut: MARGE, fin: MARGE, proprietaire: None })
    }

    /// Une copie de la trame `octets` (reçue), sans marge.
    pub fn copie(octets: &[u8]) -> Option<Paquet> {
        let tampon = faillible::copie(octets).ok()?;
        VIVANTS.fetch_add(tampon.capacity(), Ordering::Relaxed);
        Some(Paquet { tampon, debut: 0, fin: octets.len(), proprietaire: None })
    }

    /// Les données.
    pub fn donnees(&self) -> &[u8] {
        &self.tampon[self.debut..self.fin]
    }

    pub fn donnees_mut(&mut self) -> &mut [u8] {
        &mut self.tampon[self.debut..self.fin]
    }

    pub fn longueur(&self) -> usize {
        self.fin - self.debut
    }

    /// Ajoute `n` octets à la fin des données (le `skb_put`) : la place
    /// réservée à la création. None : il n'y en a plus.
    pub fn ajouter_fin(&mut self, n: usize) -> Option<&mut [u8]> {
        let fin = self.fin.checked_add(n).filter(|&f| f <= self.tampon.len())?;
        let debut = core::mem::replace(&mut self.fin, fin);
        Some(&mut self.tampon[debut..fin])
    }

    /// Ajoute un en-tête de `n` octets devant les données (le `skb_push`),
    /// dans la marge. None : la marge est épuisée.
    pub fn ajouter_entete(&mut self, n: usize) -> Option<&mut [u8]> {
        self.debut = self.debut.checked_sub(n)?;
        Some(&mut self.tampon[self.debut..self.debut + n])
    }

    /// La taille vraie du paquet (le `truesize` de Linux) : son tampon, plus
    /// ce que coûtent ses structures chez Linux, pour que les limites des
    /// files comptent à peu près comme les siennes.
    pub fn taille_vraie(&self) -> usize {
        self.tampon.capacity() + SURCOUT
    }

    /// Retire les `n` premiers octets des données (le `skb_pull`), et les
    /// rend. None : il y en a moins.
    pub fn retirer_entete(&mut self, n: usize) -> Option<&[u8]> {
        if n > self.longueur() {
            return None;
        }
        let debut = self.debut;
        self.debut += n;
        Some(&self.tampon[debut..debut + n])
    }

    /// Garde les `n` premiers octets des données (le `skb_trim`) : la
    /// longueur que dit un en-tête, quand la trame en portait plus
    /// (le bourrage d'une trame Ethernet trop courte). Plus que la
    /// longueur : rien ne change.
    pub fn couper(&mut self, n: usize) {
        self.fin = self.fin.min(self.debut + n);
    }
}

impl Paquet {
    /// Ce paquet tient sa socket jusqu'à ce que la carte l'ait fini (`skb_set_owner_w`,
    /// `tcp_wfree`) ; `numero`, celui de cet envoi.
    pub fn attacher(&mut self, retenue: &Arc<Retenue>, numero: u64) {
        let taille = self.taille_vraie();
        retenue.octets.fetch_add(taille, Ordering::Relaxed);
        self.proprietaire = Some(Proprietaire { retenue: retenue.clone(), taille, numero });
    }

    /// `skb_orphan` : il n'attendra pas (`lo`).
    pub fn orpheliner(&mut self) {
        if let Some(p) = self.proprietaire.take() {
            p.rendre();
        }
    }

    /// Le lien passe à ce qui garde la trame (une case de la carte).
    pub fn prendre_proprietaire(&mut self) -> Option<Proprietaire> {
        self.proprietaire.take()
    }

    /// La socket qu'il tient, s'il en tient une (pour ses morceaux, ipv4::fragmenter).
    pub fn retenue(&self) -> Option<&Arc<Retenue>> {
        self.proprietaire.as_ref().map(|p| &p.retenue)
    }
}

impl Drop for Paquet {
    fn drop(&mut self) {
        VIVANTS.fetch_sub(self.tampon.capacity(), Ordering::Relaxed);
        self.orpheliner();
    }
}
