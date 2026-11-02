//! Le générateur aléatoire de Linux (drivers/char/random.c, depuis 5.17),
//! sans le matériel : le réservoir où l'on verse l'aléa recueilli, le
//! générateur ChaCha20 qu'il ensemence, et leurs règles. Le noyau
//! (noyau/src/aleatoire.rs) y ajoute les sources (le processeur, les
//! interruptions, la gigue, virtio-rng), les verrous et l'heure ; ici,
//! tout ce qui vient du dehors est un argument, pour que l'hôte vérifie
//! chaque règle.
//!
//! LE RÉSERVOIR (`Reservoir`, l'`input_pool`) : un hachage BLAKE2s en
//! cours, dans lequel tout est versé (`melanger`), crédité ou non : verser
//! ne peut que mêler, jamais retirer de l'imprévisible ; et un compte des
//! bits « crédités », ceux dont une source garantit qu'ils sont
//! imprévisibles, jusqu'à 256 (la taille d'une empreinte). À 128 bits, le
//! générateur est « au début » (CRNG_EARLY) ; à 256, il est PRÊT
//! (CRNG_READY), et le reste : le compte ne sert plus.
//!
//! L'EXTRACTION (`extraire`, l'`extract_entropy` de Linux, une
//! construction à la HKDF) : l'empreinte du réservoir devient une graine,
//! d'où l'on tire la clé d'un réservoir neuf (le hachage repart, sous
//! cette clé : ce qui a été extrait ne se retrouve plus) puis la sortie,
//! 32 octets à la fois ; chaque bloc haché contient aussi 32 octets
//! d'appoint (RDSEED, RDRAND ou le compteur de cycles), que le noyau
//! fournit par une fonction, appelée seulement quand une extraction a lieu
//! (Linux ne lit RDSEED que dans `extract_entropy`), et un compteur.
//!
//! LE GÉNÉRATEUR (`Generateur`, `base_crng` et les `crngs` par processeur) :
//! une clé ChaCha20 de base, extraite du réservoir, et sa génération ;
//! une clé « du processeur » (un seul chez nous), dérivée de la clé de
//! base quand la génération a changé. Chaque demande fait un bloc
//! ChaCha20 sous la clé du processeur, dont les 32 premiers octets
//! REMPLACENT aussitôt cette clé (« fast key erasure », Bernstein 2017) :
//! qui volerait la clé plus tard ne saurait rien de ce qui a été tiré
//! avant. Les 32 autres octets, puis les blocs suivants du même état,
//! servent la demande.
//!
//! LE RÉENSEMENCEMENT (`reensemencer`, `crng_reseed`) : une nouvelle clé de
//! base extraite du réservoir, et la génération suivante (les clés des
//! processeurs se rafraîchissent alors d'elles-mêmes) ; toutes les 60 s,
//! plus souvent au début (la moitié du temps depuis le démarrage, au moins
//! 1 s, tant qu'il est sous 120 s : `crng_reseed_interval`), pour qu'un
//! aléa recueilli tôt serve vite.
//!
//! AVANT D'ÊTRE PRÊT (`crng_make_state`) : on tire quand même (le noyau en a
//! besoin dès le démarrage), directement de la clé de base, par
//! effacement de clé ; tant que rien n'a été crédité (EMPTY), une
//! nouvelle clé de base est extraite du réservoir à CHAQUE demande, pour
//! que tout ce qui a été versé entre-temps serve aussitôt.
//!
//! Pourquoi la génération : le réensemencement ne touche qu'à la clé de
//! base, sous son verrou ; chaque processeur voit au passage que la
//! génération a changé et se rafraîchit, sans que le réensemencement ait à
//! les visiter tous. Avec un seul processeur, c'est la même chose, en
//! plus court ; la structure reste celle de Linux, pour le multiprocesseur.
//!
//! LES LOTS (`Lot`, le `batched_entropy_u32` de Linux) : les petits tirages
//! du noyau (un port, un délai) se servent dans 96 octets tirés d'avance
//! (les 32 de l'effacement de clé plus un bloc), chaque valeur effacée une
//! fois rendue, le lot jeté si la génération change.
//!
//! LE PETIT RÉSERVOIR DES INTERRUPTIONS (`PetitReservoir`, le `fast_pool`
//! de Linux) : brassé à chaque interruption d'un périphérique par deux
//! permutations de SipHash (rapide, et assez pour des entrées qui ne sont
//! pas choisies par un attaquant), il est versé dans le grand réservoir
//! après 1024 interruptions ou une seconde, crédité d'un bit par 64
//! interruptions (au moins 1, au plus 128 : les deux mots versés).
//!
//! EFFACER : les clés et états passent par `&mut`, et les copies de
//! travail sont effacées par `crate::effacer`.

use crate::blake2s::{self, Blake2s};
use crate::chacha20;
use crate::siphash;
use crate::{effacer, effacer_mots};

/// Le nombre de bits crédités pour être prêt (POOL_READY_BITS), et au
/// début (POOL_EARLY_BITS).
pub const BITS_PRET: u32 = 256;
pub const BITS_DEBUT: u32 = 128;
/// L'intervalle de réensemencement, et celui du début, en secondes
/// (CRNG_RESEED_INTERVAL, CRNG_RESEED_START_INTERVAL).
pub const INTERVALLE: u64 = 60;
pub const INTERVALLE_DEBUT: u64 = 1;
/// La taille d'un lot : un bloc et demi.
pub const LOT: usize = chacha20::BLOC * 3 / 2;

/// L'état du générateur (`crng_init`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Etat {
    /// Rien de crédité encore (CRNG_EMPTY).
    Vide,
    /// Au moins 128 bits (CRNG_EARLY).
    Debut,
    /// 256 bits : prêt (CRNG_READY).
    Pret,
}

/// Le réservoir d'entrée.
pub struct Reservoir {
    hachage: Blake2s,
    bits: u32,
}

impl Default for Reservoir {
    fn default() -> Reservoir {
        Reservoir::new()
    }
}

impl Reservoir {
    /// Un réservoir vide : BLAKE2s-256 sans clé, rien de crédité.
    pub fn new() -> Reservoir {
        Reservoir { hachage: Blake2s::new(blake2s::EMPREINTE_MAX, &[]), bits: 0 }
    }

    /// Verse `octets`, sans crédit (`mix_pool_bytes`).
    pub fn melanger(&mut self, octets: &[u8]) {
        self.hachage.update(octets);
    }

    /// Les bits crédités jusqu'ici.
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Crédite `bits` (au plus 256 en tout) ; rend le compte d'avant et
    /// celui d'après, d'où l'appelant voit les seuils franchis.
    fn crediter(&mut self, bits: u32) -> (u32, u32) {
        let avant = self.bits;
        self.bits = avant.saturating_add(bits.min(BITS_PRET)).min(BITS_PRET);
        (avant, self.bits)
    }

    /// Extrait `sortie.len()` octets (`extract_entropy`), avec les 32
    /// octets d'`appoint` : la graine (l'empreinte du réservoir), puis la
    /// clé du réservoir suivant, BLAKE2s(graine, appoint ‖ 0), puis chaque
    /// morceau de 32 octets, BLAKE2s(graine, appoint ‖ n). Le bloc haché a
    /// la disposition de celui de Linux sur 64 bits : 32 octets puis un
    /// compteur de 8 octets, petit-boutiste.
    pub fn extraire(&mut self, sortie: &mut [u8], appoint: &mut dyn FnMut() -> [u8; 32]) {
        let mut graine = [0u8; blake2s::EMPREINTE_MAX];
        self.hachage.finale(&mut graine);
        let mut bloc = [0u8; 40];
        bloc[..32].copy_from_slice(&appoint());
        let mut cle_suivante = [0u8; blake2s::EMPREINTE_MAX];
        blake2s::blake2s(&mut cle_suivante, &bloc, &graine);
        self.hachage = Blake2s::new(blake2s::EMPREINTE_MAX, &cle_suivante);
        effacer(&mut cle_suivante);
        for (n, morceau) in sortie.chunks_mut(blake2s::EMPREINTE_MAX).enumerate() {
            bloc[32..].copy_from_slice(&(n as u64 + 1).to_le_bytes());
            blake2s::blake2s(morceau, &bloc, &graine);
        }
        effacer(&mut graine);
        effacer(&mut bloc);
    }
}

/// L'intervalle avant le prochain réensemencement, en secondes, à
/// `depuis` secondes du démarrage (`crng_reseed_interval`).
pub fn intervalle(depuis: u64) -> u64 {
    if depuis < INTERVALLE * 2 { (depuis / 2).max(INTERVALLE_DEBUT) } else { INTERVALLE }
}

/// Un bloc sous `cle`, dont les 32 premiers octets remplacent aussitôt la
/// clé ; `etat` reçoit l'état de ChaCha20 qui a fait ce bloc (sa clé est
/// l'ANCIENNE clé, et son compteur à 1 : à effacer après usage, ou à
/// écraser), et `alea` les octets 32 à 32 + `alea.len()` du bloc (32 au
/// plus) : le `crng_fast_key_erasure` de Linux.
pub fn effacement_de_cle(cle: &mut [u8; chacha20::CLE], etat: &mut [u32; 16], alea: &mut [u8]) {
    assert!(alea.len() <= 32);
    chacha20::initialiser(etat, cle);
    let mut premier = [0u8; chacha20::BLOC];
    chacha20::bloc(etat, &mut premier);
    cle.copy_from_slice(&premier[..chacha20::CLE]);
    alea.copy_from_slice(&premier[chacha20::CLE..chacha20::CLE + alea.len()]);
    effacer(&mut premier);
}

/// Le générateur : la clé de base, sa génération et l'état, puis la clé
/// du processeur et la génération qu'elle a vue.
pub struct Generateur {
    base: [u8; chacha20::CLE],
    generation: u64,
    etat: Etat,
    cle: [u8; chacha20::CLE],
    vue: u64,
    /// Quand réensemencer (en secondes depuis le démarrage), une fois prêt.
    prochain: u64,
}

/// Ce qu'a fait un crédit : le seuil qu'il a franchi.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Seuil {
    Aucun,
    Debut,
    Pret,
}

impl Default for Generateur {
    fn default() -> Generateur {
        Generateur::new()
    }
}

impl Generateur {
    /// Un générateur vide. La génération de la clé du processeur part à
    /// la valeur interdite (`u64::MAX`, l'`ULONG_MAX` de Linux) : son
    /// premier tirage prête se rafraîchit forcément.
    pub const fn new() -> Generateur {
        Generateur { base: [0; chacha20::CLE], generation: 0, etat: Etat::Vide, cle: [0; chacha20::CLE], vue: u64::MAX, prochain: 0 }
    }

    pub fn etat(&self) -> Etat {
        self.etat
    }

    pub fn pret(&self) -> bool {
        self.etat == Etat::Pret
    }

    /// La génération de la clé de base (les lots la comparent).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Crédite `bits` au réservoir (le `credit_init_bits` de Linux, qui ne
    /// fait plus rien une fois prêt), à `depuis` secondes du démarrage, et
    /// rend le seuil franchi : à 128 bits, la clé de base extraite si rien
    /// ne l'a été (EMPTY → EARLY) ; à 256, le premier réensemencement, et
    /// prêt.
    pub fn crediter(&mut self, r: &mut Reservoir, bits: u32, depuis: u64, appoint: &mut dyn FnMut() -> [u8; 32]) -> Seuil {
        if self.pret() || bits == 0 {
            return Seuil::Aucun;
        }
        let (avant, apres) = r.crediter(bits);
        if avant < BITS_PRET && apres >= BITS_PRET {
            self.reensemencer(r, depuis, appoint);
            Seuil::Pret
        } else if avant < BITS_DEBUT && apres >= BITS_DEBUT {
            if self.etat == Etat::Vide {
                r.extraire(&mut self.base, appoint);
                self.etat = Etat::Debut;
            }
            Seuil::Debut
        } else {
            Seuil::Aucun
        }
    }

    /// Une nouvelle clé de base extraite du réservoir, la génération
    /// suivante (jamais `u64::MAX`), prêt, et la prochaine échéance
    /// (`crng_reseed`).
    pub fn reensemencer(&mut self, r: &mut Reservoir, depuis: u64, appoint: &mut dyn FnMut() -> [u8; 32]) {
        r.extraire(&mut self.base, appoint);
        self.generation = self.generation.wrapping_add(1);
        if self.generation == u64::MAX {
            self.generation = 0;
        }
        self.etat = Etat::Pret;
        self.prochain = depuis.saturating_add(intervalle(depuis));
    }

    /// Faut-il réensemencer, à `depuis` secondes du démarrage ?
    pub fn a_reensemencer(&self, depuis: u64) -> bool {
        self.pret() && depuis >= self.prochain
    }

    /// Prépare un tirage (`crng_make_state`) : `etat` reçoit un état de
    /// ChaCha20 dont les blocs suivants serviront la suite de la demande,
    /// et `alea` (32 octets au plus) les premiers octets. Pas prêt : par
    /// effacement de la clé de base elle-même, extraite d'abord du
    /// réservoir si rien n'est crédité (`appoint` sert à cette extraction).
    /// Prêt : la clé du processeur, rafraîchie de la clé de base si la
    /// génération a changé.
    pub fn preparer(&mut self, r: &mut Reservoir, appoint: &mut dyn FnMut() -> [u8; 32], etat: &mut [u32; 16], alea: &mut [u8]) {
        if !self.pret() {
            if self.etat == Etat::Vide {
                r.extraire(&mut self.base, appoint);
            }
            effacement_de_cle(&mut self.base, etat, alea);
            return;
        }
        if self.vue != self.generation {
            effacement_de_cle(&mut self.base, etat, &mut self.cle);
            self.vue = self.generation;
        }
        effacement_de_cle(&mut self.cle, etat, alea);
    }
}

/// Continue un tirage : remplit `sortie` des blocs suivants de `etat` (le
/// reste de `_get_random_bytes`), la retenue du compteur de 64 bits faite
/// comme Linux (mot 13 quand le mot 12 repasse à zéro).
pub fn continuer(etat: &mut [u32; 16], sortie: &mut [u8]) {
    for morceau in sortie.chunks_mut(chacha20::BLOC) {
        let mut b = [0u8; chacha20::BLOC];
        chacha20::bloc(etat, &mut b);
        if etat[12] == 0 {
            etat[13] = etat[13].wrapping_add(1);
        }
        morceau.copy_from_slice(&b[..morceau.len()]);
        effacer(&mut b);
    }
}

/// Donne pour clé à l'état d'un tirage les 32 octets aléatoires `cle` (le
/// `crng_make_state(chacha_state, &chacha_state.x[4], 32)` de
/// `get_random_bytes_user`). Après `preparer`, l'état garde la clé du
/// processeur d'AVANT l'effacement rapide : d'elle on refait la clé qui l'a
/// remplacée, et tous les tirages suivants. Pour un tirage vers un
/// programme, dont la copie peut dormir (une faute de page), l'état garde
/// alors une clé neuve, qui ne dit rien des autres.
pub fn cle_de_tirage(etat: &mut [u32; 16], cle: &[u8; 32]) {
    for (m, o) in etat[4..12].iter_mut().zip(cle.chunks_exact(4)) {
        *m = u32::from_le_bytes([o[0], o[1], o[2], o[3]]);
    }
}

/// Un tirage entier (`_get_random_bytes`) : les 32 premiers octets par
/// `preparer`, le reste par `continuer`, l'état effacé à la fin.
pub fn tirer(g: &mut Generateur, r: &mut Reservoir, appoint: &mut dyn FnMut() -> [u8; 32], sortie: &mut [u8]) {
    let mut etat = [0u32; 16];
    let n = sortie.len().min(32);
    let (debut, suite) = sortie.split_at_mut(n);
    g.preparer(r, appoint, &mut etat, debut);
    continuer(&mut etat, suite);
    effacer_mots(&mut etat);
}

/// Un lot d'octets tirés d'avance (`batched_entropy`).
pub struct Lot {
    octets: [u8; LOT],
    position: usize,
    generation: u64,
}

impl Default for Lot {
    fn default() -> Lot {
        Lot::new()
    }
}

impl Lot {
    /// Un lot vide (la position au bout : le premier tirage le remplit).
    pub const fn new() -> Lot {
        Lot { octets: [0; LOT], position: LOT, generation: 0 }
    }

    /// `N` octets du lot (4 pour un u32, 8 pour un u64), effacés du lot.
    /// Pas prêt : un tirage direct, sans lot (Linux aussi). Le lot est
    /// refait quand il est vide, ou que la génération a changé.
    pub fn prendre<const N: usize>(&mut self, g: &mut Generateur, r: &mut Reservoir, appoint: &mut dyn FnMut() -> [u8; 32]) -> [u8; N] {
        let mut v = [0u8; N];
        if !g.pret() {
            tirer(g, r, appoint, &mut v);
            return v;
        }
        if self.position + N > LOT || self.generation != g.generation() {
            tirer(g, r, appoint, &mut self.octets);
            self.position = 0;
            self.generation = g.generation();
        }
        v.copy_from_slice(&self.octets[self.position..self.position + N]);
        effacer(&mut self.octets[self.position..self.position + N]);
        self.position += N;
        v
    }
}

/// Le petit réservoir des interruptions (`fast_pool`).
pub struct PetitReservoir {
    v: [u64; 4],
    compte: u32,
    /// Quand il a été versé pour la dernière fois (en secondes ; l'appelant
    /// choisit l'unité, pourvu qu'il garde la même).
    dernier: u64,
}

/// Les constantes de départ de SipHash (le `pool` initial de Linux).
const DEPART: [u64; 4] = [0x736f_6d65_7073_6575, 0x646f_7261_6e64_6f6d, 0x6c79_6765_6e65_7261, 0x7465_6462_7974_6573];

impl Default for PetitReservoir {
    fn default() -> PetitReservoir {
        PetitReservoir::new()
    }
}

impl PetitReservoir {
    pub const fn new() -> PetitReservoir {
        PetitReservoir { v: DEPART, compte: 0, dernier: 0 }
    }

    /// Une interruption : le compteur de cycles `cycles` et l'adresse
    /// interrompue mêlée au numéro de l'interruption `adresse` (le
    /// `fast_mix` de Linux : SipHash-1-x d'une clé nulle, sans sécurité à
    /// lui seul, mais rapide) ; rend vrai s'il est temps de verser
    /// (1024 interruptions, ou une seconde depuis la dernière fois, à
    /// l'instant `maintenant`).
    pub fn ajouter(&mut self, cycles: u64, adresse: u64, maintenant: u64) -> bool {
        self.v[3] ^= cycles;
        siphash::tour(&mut self.v);
        self.v[0] ^= cycles;
        self.v[3] ^= adresse;
        siphash::tour(&mut self.v);
        self.v[0] ^= adresse;
        self.compte = self.compte.saturating_add(1);
        self.compte >= 1024 || maintenant >= self.dernier.saturating_add(1)
    }

    /// Ce qu'il y a à verser (`mix_interrupt_randomness`) : les deux
    /// premiers mots seulement (les deux autres restent, comme une clé pour
    /// la suite), et le crédit : un bit par 64 interruptions, entre 1 et
    /// 128 ; le compte repart de zéro. Rien si aucune interruption n'est
    /// venue.
    pub fn verser(&mut self, maintenant: u64) -> Option<([u8; 16], u32)> {
        if self.compte == 0 {
            return None;
        }
        let mut o = [0u8; 16];
        o[..8].copy_from_slice(&self.v[0].to_le_bytes());
        o[8..].copy_from_slice(&self.v[1].to_le_bytes());
        let credit = ((self.compte & 0xffff) / 64).clamp(1, 128);
        self.compte = 0;
        self.dernier = maintenant;
        Some((o, credit))
    }
}
