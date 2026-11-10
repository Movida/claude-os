//! Le réassemblage des fragments d'IPv4 (net/ipv4/ip_fragment.c et
//! inet_fragment.c de Linux).
//!
//! POURQUOI DES FRAGMENTS. Un paquet plus grand que la MTU d'un lien ne passe pas :
//! celui qui l'envoie, ou un routeur (sans le drapeau DF), le découpe. Chaque morceau a
//! son propre en-tête, le même identifiant, sa place dans le paquet d'origine en unités
//! de 8 octets, et le drapeau MF (d'autres suivent) sauf le dernier. Seule la destination
//! recolle : les morceaux peuvent suivre des chemins différents, arriver dans le
//! désordre, en double, ou jamais.
//!
//! LES RÈGLES, celles de `ip_frag_queue` :
//!   - une file par (source, destination, identifiant, protocole), ouverte par le premier
//!     morceau, et qui expire après 30 s : ce qui manque ne viendra plus ; si le premier
//!     morceau était là, l'émetteur reçoit « temps de réassemblage dépassé » ;
//!   - un morceau qui en chevauche un autre fait jeter TOUTE la file (RFC 5722, écrit pour
//!     IPv6, que Linux applique aussi à IPv4) : le chevauchement a surtout servi à
//!     passer les pare-feu, qui ne voyaient pas le même paquet que la machine visée. Un
//!     morceau en double, lui, est seulement ignoré ;
//!   - un morceau qui dit une fin contraire à celle qu'on connaît, de même ;
//!   - la mémoire est bornée : au-delà de 4 Mio (`ipfrag_high_thresh`), plus aucun morceau.
//!     Sans quoi quelques morceaux envoyés sans jamais les finir occuperaient tout ;
//!   - `ipfrag_max_dist` (64) : plus de 64 morceaux du même émetteur depuis le dernier
//!     morceau d'une file, et elle repart de rien : une file si en retard ne se finira
//!     sans doute pas, et un identifiant de 16 bits revient vite à un fort débit : ce qui
//!     arriverait maintenant serait d'un autre paquet.
//!
//! Écarté : `ip_defrag` sur le chemin de routage, nous ne routons pas ; `IPSKB_FRAG_PMTU`
//! et `frag_max_size` : ils ne servent qu'à refragmenter ce qu'on transmet.
//!
//! Ici, les règles seules, sur des morceaux que donne le noyau (noyau/src/reseau/ipv4.rs,
//! qui recopie le paquet complet).

use alloc::vec::Vec;
use faillible::VecFaillible;

/// Le temps qu'une file peut attendre (`IP_FRAG_TIME`, 30 s).
pub const DELAI: u64 = 30_000_000_000;
/// La mémoire au-delà de laquelle aucune file ne s'ouvre (`ipfrag_high_thresh`).
pub const MEMOIRE_MAX: usize = 4 << 20;
/// `ipfrag_max_dist`.
const ECART_MAX: u32 = 64;
/// Les files à la fois : un tableau pris une fois pour toutes, plutôt qu'une allocation
/// à chaque paquet ; 4 Mio de petits morceaux ne donneraient pas moins de files chez
/// Linux, mais chacune en coûte déjà trois fragments de taille vraie.
pub const FILES_MAX: usize = 128;
/// La plus grande longueur d'un paquet recollé, en-tête compris.
const PAQUET_MAX: u32 = 65_535;

/// Ce qui identifie un paquet en morceaux (`frag_v4_compare_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cle {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub identifiant: u16,
    pub protocole: u8,
}

/// Un morceau : le paquet du noyau, sans son en-tête IP.
pub trait Morceau {
    /// Les octets.
    fn octets(&self) -> &[u8];
    /// Garde les `n` premiers.
    fn couper(&mut self, n: usize);
    /// Ce qu'il occupe en mémoire.
    fn taille_vraie(&self) -> usize;
}

/// Ce que devient un morceau reçu.
#[derive(Debug, PartialEq, Eq)]
pub enum Issue<M> {
    /// Gardé : il en manque.
    EnCours,
    /// Le morceau est jeté (mauvais, en double, plus de place), et la file aussi s'il
    /// la rendait fausse.
    Jete,
    /// C'est fini : les morceaux dans l'ordre, la longueur des données, celle de l'en-tête
    /// du premier, et les bits ECN à ajouter à son TOS (`ip_frag_ecn_table`).
    Complet { morceaux: Vec<M>, longueur: u32, entete: u32, ecn: u8 },
}

/// Une suite de morceaux sans trou reçus dans l'ordre (`frag_run_len`).
#[derive(Debug, Clone, Copy)]
struct Suite {
    debut: u32,
    fin: u32,
}

struct File<M> {
    cle: Cle,
    /// Triés par place (`rb_fragments`).
    morceaux: Vec<(u32, M)>,
    suites: Vec<Suite>,
    /// La fin connue ou supposée du paquet (`q.len`), et les octets reçus (`q.meat`).
    longueur: u32,
    recu: u32,
    /// Le premier et le dernier morceau sont là (INET_FRAG_FIRST_IN, LAST_IN).
    premier: bool,
    dernier: bool,
    /// Les morceaux reçus de cette source depuis le dernier de cette file.
    ecart: u32,
    /// Quels bits ECN ont été vus (`qp->ecn`).
    ecn: u8,
    /// La longueur de l'en-tête du premier morceau, et l'interface du dernier reçu.
    entete: u32,
    interface: u32,
    echeance: u64,
    vraie: usize,
}

impl<M> File<M> {
    fn new(cle: Cle, maintenant: u64) -> File<M> {
        File { cle, morceaux: Vec::new(), suites: Vec::new(), longueur: 0, recu: 0, premier: false, dernier: false, ecart: 0, ecn: 0, entete: 0, interface: 0, echeance: maintenant + DELAI, vraie: 0 }
    }
}

/// Une file échue : le premier morceau, s'il était là (à qui dire le délai dépassé), la
/// longueur de son en-tête, et l'interface de la dernière arrivée.
pub struct Echue<M> {
    pub premier: Option<M>,
    pub entete: u32,
    pub interface: u32,
}

/// Toutes les files.
pub struct Reassemblage<M> {
    files: Vec<File<M>>,
    memoire: usize,
}

/// `ip_frag_ecn_table` : les bits ECN d'un paquet recollé, d'après ceux de ses morceaux
/// (IPFRAG_ECN_NOT_ECT 1, ECT_1 2, ECT_0 4, CE 8) ; None : un mélange impossible.
fn ecn_du_paquet(vus: u8) -> Option<u8> {
    const NOT_ECT: u8 = 1;
    const CE: u8 = 8;
    const INET_ECN_CE: u8 = 3;
    if vus & NOT_ECT != 0 && vus != NOT_ECT {
        return None;
    }
    Some(if vus & CE != 0 && vus != CE { INET_ECN_CE } else { 0 })
}

impl<M: Morceau> Reassemblage<M> {
    /// Fait la table, sa place prise (None : plus de mémoire).
    pub fn new() -> Option<Reassemblage<M>> {
        let mut files = Vec::new();
        files.try_reserve_exact(FILES_MAX).ok()?;
        Some(Reassemblage { files, memoire: 0 })
    }

    /// La mémoire que gardent les files.
    pub fn memoire(&self) -> usize {
        self.memoire
    }

    /// La prochaine expiration.
    pub fn echeance(&self) -> Option<u64> {
        self.files.iter().map(|f| f.echeance).min()
    }

    /// Une file échue, s'il y en a une (`ip_expire`).
    pub fn prendre_echue(&mut self, maintenant: u64) -> Option<Echue<M>> {
        let i = self.files.iter().position(|f| f.echeance <= maintenant)?;
        let f = self.files.swap_remove(i);
        self.memoire = self.memoire.saturating_sub(f.vraie);
        let (entete, interface) = (f.entete, f.interface);
        let premier = if f.premier { f.morceaux.into_iter().next().map(|(_, m)| m) } else { None };
        Some(Echue { premier, entete, interface })
    }

    /// Le morceau `charge` (sans en-tête) du paquet `cle`, à `decalage` octets du début,
    /// `suite` : MF ; `tos` : celui de son en-tête ; `entete` : la longueur de son en-tête
    /// (`ip_defrag`, `ip_frag_queue`).
    pub fn recevoir(&mut self, cle: Cle, decalage: u32, suite: bool, tos: u8, entete: u32, mut charge: M, interface: u32, maintenant: u64) -> Issue<M> {
        // Au-delà de `ipfrag_high_thresh`, tout morceau est jeté, même d'une file déjà ouverte
        // (`inet_frag_find` : pas de file trouvée). Sans quoi un paquet commencé avant le seuil
        // pourrait continuer à grossir.
        if self.memoire > MEMOIRE_MAX {
            return Issue::Jete;
        }
        // Un morceau de plus de cette source : les autres files s'éloignent.
        for f in self.files.iter_mut().filter(|f| f.cle.source == cle.source) {
            f.ecart = f.ecart.saturating_add(1);
        }
        let i = match self.files.iter().position(|f| f.cle == cle) {
            Some(i) => i,
            None => {
                if self.files.len() == self.files.capacity() {
                    return Issue::Jete;
                }
                self.files.ajouter_dans_la_place(File::new(cle, maintenant));
                self.files.len() - 1
            }
        };
        // `ip_frag_too_far`, `ip_frag_reinit` : la file repart de rien, son délai aussi.
        if self.files[i].ecart > ECART_MAX && !self.files[i].morceaux.is_empty() {
            let v = self.files[i].vraie;
            self.memoire = self.memoire.saturating_sub(v);
            self.files[i] = File::new(cle, maintenant);
        }
        self.files[i].ecart = 0;
        let ecn = 1u8 << (tos & 3);
        let mut fin = decalage + charge.octets().len() as u32;
        let f = &mut self.files[i];
        if !suite {
            // Le dernier : rien au-delà, et une seule fin possible.
            if fin < f.longueur || (f.dernier && fin != f.longueur) {
                self.retirer(i);
                return Issue::Jete;
            }
            f.dernier = true;
            f.longueur = fin;
        } else {
            // Un morceau qui n'est pas le dernier fait un multiple de 8 octets.
            fin &= !7;
            if fin > f.longueur {
                if f.dernier {
                    self.retirer(i);
                    return Issue::Jete;
                }
                f.longueur = fin;
            }
        }
        if fin == decalage {
            self.retirer(i);
            return Issue::Jete;
        }
        charge.couper((fin - decalage) as usize);
        match inserer(f, decalage, fin) {
            Insertion::Ok(place) => {
                if f.morceaux.try_reserve(1).is_err() {
                    self.retirer(i);
                    return Issue::Jete;
                }
                let v = charge.taille_vraie();
                f.morceaux.inserer_dans_la_place(place, (decalage, charge));
                f.vraie += v;
                self.memoire += v;
            }
            Insertion::Double => return Issue::Jete,
            Insertion::Chevauchement => {
                self.retirer(i);
                return Issue::Jete;
            }
        }
        let f = &mut self.files[i];
        f.interface = interface;
        f.ecn |= ecn;
        f.recu += fin - decalage;
        if decalage == 0 {
            f.premier = true;
            f.entete = entete;
        }
        if f.premier && f.dernier && f.recu == f.longueur {
            let (longueur, entete, vus, v) = (f.longueur, f.entete, f.ecn, f.vraie);
            self.memoire = self.memoire.saturating_sub(v);
            let f = self.files.swap_remove(i);
            // `ip_frag_reasm`.
            let Some(ecn) = ecn_du_paquet(vus) else { return Issue::Jete };
            if entete + longueur > PAQUET_MAX {
                return Issue::Jete;
            }
            // (Pris une fois : la mémoire de la file sert encore ; en cas d'échec, tout est
            // jeté, le paquet est perdu.)
            let mut morceaux = Vec::new();
            if morceaux.try_reserve_exact(f.morceaux.len()).is_err() {
                return Issue::Jete;
            }
            for (_, m) in f.morceaux {
                morceaux.ajouter_dans_la_place(m);
            }
            return Issue::Complet { morceaux, longueur, entete, ecn };
        }
        Issue::EnCours
    }

    /// `inet_frag_kill`.
    fn retirer(&mut self, i: usize) {
        let f = self.files.swap_remove(i);
        self.memoire = self.memoire.saturating_sub(f.vraie);
    }
}

enum Insertion {
    /// À cette place dans la file.
    Ok(usize),
    Double,
    Chevauchement,
}

/// `inet_frag_queue_insert` (RFC 5722, avec son errata 3089) : la place du morceau
/// [`debut`, `fin`[, d'après les suites déjà là ; un morceau tout entier dans une suite est
/// un double ; à cheval, un chevauchement. Une suite grandit seulement au bout de la
/// dernière : ce qui arrive dans l'ordre, le cas ordinaire, en reste à une seule.
fn inserer<M: Morceau>(f: &mut File<M>, debut: u32, fin: u32) -> Insertion {
    if f.suites.try_reserve(1).is_err() {
        return Insertion::Chevauchement;
    }
    let bout = f.morceaux.last().map(|(d, m)| *d + m.octets().len() as u32);
    match bout {
        None => f.suites.ajouter_dans_la_place(Suite { debut, fin }),
        Some(b) if b < fin => {
            if debut < b {
                return Insertion::Chevauchement;
            }
            match f.suites.last_mut() {
                Some(s) if debut == b => s.fin = fin,
                _ => f.suites.ajouter_dans_la_place(Suite { debut, fin }),
            }
            return Insertion::Ok(f.morceaux.len());
        }
        Some(_) => {
            let mut place = f.suites.len();
            for (k, s) in f.suites.iter().enumerate() {
                if fin <= s.debut {
                    place = k;
                    break;
                }
                if debut >= s.fin {
                    continue;
                }
                return if debut >= s.debut && fin <= s.fin { Insertion::Double } else { Insertion::Chevauchement };
            }
            f.suites.inserer_dans_la_place(place, Suite { debut, fin });
            return Insertion::Ok(f.morceaux.partition_point(|(d, _)| *d < debut));
        }
    }
    Insertion::Ok(0)
}
