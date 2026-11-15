//! IGMP (RFC 2236 et 3376) : ce que la machine dit aux routeurs de son lien
//! de ses groupes, pour qu'ils les lui fassent parvenir. Recopié de
//! net/ipv4/igmp.c (ce qu'ajoute `CONFIG_IP_MULTICAST`), fonction par
//! fonction ; chacune dit son nom.
//!
//! Ce qui se dit, en IGMPv3 (la version de Linux tant qu'aucun vieux
//! routeur ne s'est fait entendre) :
//!   - à chaque changement d'un filtre (une adhésion, un départ, une
//!     source) : un rapport de changement, deux jiffies après, puis `qrv`
//!     autres au hasard dans la seconde (`igmp_ifc_event`) ; chaque groupe
//!     et chaque source qui a changé y paraît `qrv` fois (ses `crcount`) :
//!     un mode qui change (TO_EX, TO_IN), des sources qui entrent (ALLOW)
//!     ou qui sortent (BLOCK), un groupe parti (TO_IN {}, gardé dans les
//!     tombes de l'interface le temps de le dire) ;
//!   - à une requête du routeur : l'état courant (IS_EX, IS_IN) de tous les
//!     groupes, ou de celui qu'elle nomme, au hasard dans le délai qu'elle
//!     donne.
//!
//! En v1 et v2 (après une requête d'un routeur de cette version, pour
//! `qrv × qi + qri`, 260 s) : un rapport de 8 octets vers le groupe
//! lui-même, deux fois à l'adhésion (`unsolicit_count`) et à chaque
//! requête, et en v2 un départ vers 224.0.0.2 si le dernier rapport sur ce
//! groupe venait de nous.
//!
//! Le temps : les minuteurs de Linux (un par interface pour les rapports de
//! changement, un pour la réponse à une requête générale, un par groupe)
//! sont ici des échéances, en ns : le noyau donne l'heure (`regler`),
//! demande la prochaine échéance (`prochaine_echeance`) et appelle `temps`
//! quand elle est passée. Les délais restent comptés en jiffies, comme
//! chez Linux (« + 2 », le hasard d'`igmp_start_timer`), à la fréquence de
//! notre horloge (`HZ`).
//!
//! Choix de conception : les rapports sont faits ici, en octets (le message
//! IGMP, sans l'en-tête IP), et attendent dans `Groupes::envois` que le
//! noyau les prenne, son verrou lâché. Linux les envoie dans la fonction
//! qui les décide (`igmpv3_sendpack`, sous le `rtnl_lock` et le verrou du
//! groupe), ce qui ne se peut pas ici : l'envoi prend les verrous de la
//! table de routage, des MTU, de la carte, que l'ordre des verrous du noyau
//! ne met jamais sous celui des groupes ; et une copie rendue à la machine
//! reviendrait dans `recevoir` sous ce même verrou. Écarté aussi : un
//! rappel du noyau pour chaque rapport (la bibliothèque saurait comment le
//! noyau envoie). Le prix : un rapport part un peu après sa décision, dans
//! le même appel système ou le même tour de la tâche du réseau.

use super::{Contexte, Groupe, Groupes, Horloge, Interface, Mode, Source, TOUS_LES_HOTES};
use alloc::vec::Vec;
use faillible::VecFaillible;
use formats::reseau::igmp::{
    self, ANCIENNES, DEPART, EST_EXCLURE, EST_INCLURE, Igmp, NOUVELLES, RAPPORT_V1, RAPPORT_V2, REQUETE, RequeteV3,
    VERS_EXCLURE, VERS_INCLURE,
};
use formats::reseau::ipv4;

/// La fréquence des jiffies de nos délais : celle de l'horloge du noyau
/// (horloge.rs, qui le vérifie). Linux a la sienne (CONFIG_HZ) ; les
/// délais d'IGMP ne changent pas de durée, seulement de grain.
pub const HZ: u64 = 1000;
const JIFFY: u64 = 1_000_000_000 / HZ;
const SECONDE: u64 = 1_000_000_000;

/// Les réglages de Linux, à leur valeur par défaut (pas de sysctl ici) :
/// combien de rapports répètent un changement (`igmp_qrv`), l'intervalle
/// des requêtes et leur délai de réponse supposés tant qu'aucune requête
/// v3 ne les a dits (IGMP_QUERY_INTERVAL, IGMP_QUERY_RESPONSE_INTERVAL),
/// le délai du premier rapport v1 ou v2 (IGMP_INITIAL_REPORT_DELAY, en
/// jiffies), l'intervalle des rapports non sollicités en v1 et v2, puis en
/// v3 (en ms), et les groupes du lien (224.0.0.0/24) annoncés comme les
/// autres (`igmp_link_local_mcast_reports`).
pub(super) const QRV: u8 = 2;
pub(super) const INTERVALLE_DES_REQUETES: u64 = 125 * SECONDE;
pub(super) const DELAI_DE_REPONSE: u64 = 10 * SECONDE;
const DELAI_INITIAL: u32 = 1;
const NON_SOLLICITE_V2: u32 = 10_000;
const NON_SOLLICITE_V3: u32 = 1_000;
const RAPPORTS_DU_LIEN: bool = true;
/// La plus petite MTU d'IPv4 (IPV4_MIN_MTU) ; la plus grande (IP_MAX_MTU).
const MTU_MIN: u32 = 68;
const MTU_MAX: u32 = 65535;
/// L'en-tête IP d'un rapport : 20 octets, et l'alerte aux routeurs (4).
const ENTETE_IP: usize = 24;
/// La plus petite place qu'on essaie d'avoir pour un rapport.
const PLACE_MIN: usize = 256;

/// Un message à envoyer : par l'interface `interface`, vers `destination`.
/// Sa source est celle que propose la route ; pour un rapport v3, elle doit
/// être une adresse de cette interface, sinon 0.0.0.0 (RFC 3376, 4.2.13 :
/// `igmpv3_get_srcaddr`). Le message est complet, somme comprise.
pub struct Envoi {
    pub interface: u32,
    pub destination: [u8; 4],
    pub v3: bool,
    pub octets: Vec<u8>,
}

fn ms_en_jiffies(ms: u32) -> u32 {
    ((ms as u64 * HZ).div_ceil(1000) as u32).max(1)
}

/// L'échéance d'un minuteur armé au hasard dans `max` jiffies, plus 2
/// (`igmp_start_timer`, `igmp_ifc_start_timer`, `igmp_gq_start_timer` :
/// « jiffies + tv + 2 »).
fn au_hasard(h: Horloge, max: u32) -> u64 {
    h.maintenant + ((h.alea)(max) as u64 + 2) * JIFFY
}


/// Ce groupe ne s'annonce jamais : 224.0.0.1 (tous les hôtes), et, sans
/// `igmp_link_local_mcast_reports`, ceux du lien.
fn muet(groupe: [u8; 4]) -> bool {
    groupe == TOUS_LES_HOTES || (ipv4::multidiffusion_du_lien(groupe) && !RAPPORTS_DU_LIEN)
}

impl Groupe {
    /// `igmp_start_timer`.
    fn armer(&mut self, h: Horloge, max: u32) {
        self.minuteur = Some(au_hasard(h, max));
    }

    /// `igmp_stop_timer`.
    fn arreter(&mut self) {
        self.minuteur = None;
        self.rapporteur = false;
        self.non_sollicites = 0;
    }

    /// `igmp_mod_timer` : un minuteur qui tourne et finit avant `max`
    /// jiffies est gardé ; sinon, réarmé au hasard dans `max`.
    fn rearmer(&mut self, h: Horloge, max: u32) {
        self.non_sollicites = 0;
        if self.minuteur.is_some_and(|e| e.saturating_sub(h.maintenant) < max as u64 * JIFFY) {
            return;
        }
        self.armer(h, max);
    }

    /// Une source entre-t-elle dans le filtre de l'interface ?
    fn entre(&self, s: &Source) -> bool {
        if self.comptes[Mode::Exclure as usize] != 0 {
            self.comptes[Mode::Exclure as usize] == s.exclus() && s.inclus() == 0
        } else {
            s.inclus() != 0
        }
    }

    /// `sf_markstate` : note, avant un changement, les sources qui entrent.
    pub(super) fn markstate(&mut self) {
        for k in 0..self.sources.len() {
            self.sources[k].avant = self.entre(&self.sources[k]);
        }
    }

    /// `sf_setstate`, après le changement : chaque source qui entre
    /// maintenant et n'entrait pas sera annoncée `qrv` fois (et quitte la
    /// tombe si elle y était) ; chaque source qui entrait et n'entre plus
    /// va dans la tombe (ou y reste), pour `qrv` rapports. Rend le nombre de
    /// sources qui ont changé.
    pub(super) fn setstate(&mut self, qrv: u8) -> u32 {
        let mut changees = 0;
        for k in 0..self.sources.len() {
            let maintenant = self.entre(&self.sources[k]);
            let s = self.sources[k];
            let t = self.tombe.iter().position(|x| x.adresse == s.adresse);
            if maintenant {
                if !s.avant {
                    if let Some(t) = t {
                        self.tombe.remove(t);
                        ranger(&mut self.tombe);
                    }
                    self.sources[k].crcount = qrv;
                    changees += 1;
                }
            } else if s.avant {
                self.sources[k].crcount = 0;
                // « add or update "delete" records if an active filter is
                // now inactive » : une copie de la source, en tête ; sans
                // mémoire, rien (comme le `continue` de Linux).
                let t = match t {
                    Some(t) => t,
                    None if self.tombe.inserer(0, s).is_ok() => 0,
                    None => continue,
                };
                self.tombe[t].crcount = qrv;
                changees += 1;
            }
        }
        changees
    }

    /// Les lignes d'IGMP d'un changement de mode (`ip_mc_add_src`,
    /// `ip_mc_del_src`) : `qrv` rapports diront le mode, et aucun ne
    /// redira les sources (RFC 3376, 5.1 : pas d'enregistrement de sources
    /// avec un changement de mode).
    pub(super) fn changement_de_mode(&mut self, qrv: u8) {
        self.crcount = qrv;
        for s in self.sources.iter_mut() {
            s.crcount = 0;
        }
    }

    /// `igmp_xmarksources` : une requête qui nomme des sources, pour un
    /// groupe en EXCLUDE ; faut-il répondre (pas si elles sont toutes
    /// exclues) ?
    fn xmarksources(&mut self, r: &RequeteV3) -> bool {
        let n = r.nombre();
        let mut vues = 0;
        for s in self.sources.iter() {
            if vues == n {
                break;
            }
            for x in r.sources() {
                // « skip inactive filters »
                if s.inclus() != 0 || self.comptes[Mode::Exclure as usize] != s.exclus() {
                    break;
                }
                if x == s.adresse {
                    vues += 1;
                    break;
                }
            }
        }
        self.demande = false;
        vues != n
    }

    /// `igmp_marksources` : note les sources que nomme la requête `r` (en
    /// INCLUDE) ; faut-il répondre (une au moins est à nous) ?
    fn marksources(&mut self, r: &RequeteV3) -> bool {
        if self.mode == Mode::Exclure {
            return self.xmarksources(r);
        }
        let n = r.nombre();
        let mut vues = 0;
        for s in self.sources.iter_mut() {
            if vues == n {
                break;
            }
            if r.sources().any(|x| x == s.adresse) {
                s.demandee = true;
                vues += 1;
            }
        }
        self.demande = vues != 0;
        self.demande
    }
}

/// Ce qu'un enregistrement lit d'un groupe pendant qu'il en parcourt les
/// sources.
#[derive(Clone, Copy)]
struct Etat {
    mode: Mode,
    comptes: [u32; 2],
    demande: bool,
    crcount: u8,
}

/// `is_in` : la source `s` paraît-elle dans un enregistrement de genre
/// `genre` (`gparti` : le groupe est parti ; `sparti` : la source) ?
fn is_in(g: Etat, s: &Source, genre: u8, gparti: bool, sparti: bool) -> bool {
    let exclus = g.comptes[Mode::Exclure as usize];
    match genre {
        EST_INCLURE | EST_EXCLURE => {
            if gparti || sparti {
                return false;
            }
            if !(g.demande && !s.demandee) {
                if g.mode == Mode::Inclure {
                    return true;
                }
                // « don't include if this source is excluded in all filters »
                if s.inclus() != 0 {
                    return genre == EST_INCLURE;
                }
                return exclus == s.exclus();
            }
            false
        }
        VERS_INCLURE => !(gparti || sparti) && s.inclus() != 0,
        VERS_EXCLURE => {
            if gparti || sparti || exclus == 0 || s.inclus() != 0 {
                return false;
            }
            exclus == s.exclus()
        }
        NOUVELLES => !(gparti || s.crcount == 0) && ((g.mode == Mode::Inclure) ^ sparti),
        ANCIENNES => {
            if g.mode == Mode::Inclure {
                return gparti || (s.crcount != 0 && sparti);
            }
            s.crcount != 0 && !gparti && !sparti
        }
        _ => false,
    }
}

/// Un rapport v3 qui se remplit (le `skb` d'`igmpv3_newpack`) : le message
/// IGMP, dans une place prise d'un coup, que rien ne dépasse.
struct Paquet {
    octets: Vec<u8>,
    taille: usize,
}

impl Paquet {
    /// `igmpv3_newpack` : la place d'un paquet de la MTU (au plus 65535
    /// octets), divisée par deux tant que le tas la refuse, jusqu'à 256 ; puis
    /// l'en-tête du rapport, sans enregistrement. Le paquet IP y prendra 24
    /// octets.
    fn nouveau(mtu: u32) -> Option<Paquet> {
        let mut taille = mtu.min(MTU_MAX) as usize;
        loop {
            let place = taille.checked_sub(ENTETE_IP)?;
            if let Ok(mut octets) = faillible::avec_capacite::<u8>(place) {
                octets.ajouter_tranche(&igmp::RAPPORT_V3_VIDE).ok()?;
                return Some(Paquet { octets, taille: place });
            }
            taille >>= 1;
            if taille < PLACE_MIN {
                return None;
            }
        }
    }

    /// La place qui reste (`skb_availroom`).
    fn place(&self) -> usize {
        self.taille - self.octets.len()
    }

    /// `skb_put` : dans la place réservée, que les appelants ont vérifiée
    /// (Linux s'arrête net sinon, `skb_over_panic`).
    fn mettre(&mut self, o: &[u8]) {
        for &x in o {
            self.octets.ajouter_dans_la_place(x);
        }
    }

    fn enregistrements(&self) -> u16 {
        u16::from_be_bytes([self.octets[6], self.octets[7]])
    }
}

/// `AVAILABLE` : la place du paquet en cours, 0 sans paquet.
fn place(p: &Option<Paquet>) -> usize {
    p.as_ref().map_or(0, Paquet::place)
}

/// Où vont les rapports d'une interface.
struct Sortie<'a> {
    index: u32,
    h: Horloge,
    envois: &'a mut Vec<Envoi>,
}

impl Sortie<'_> {
    /// `igmpv3_sendpack` : la somme, puis l'envoi (vers 224.0.0.22). Sans
    /// mémoire pour le garder, perdu.
    fn envoyer(&mut self, mut p: Paquet) {
        igmp::sceller(&mut p.octets);
        let _ = self.envois.ajouter(Envoi { interface: self.index, destination: igmp::ROUTEURS_V3, v3: true, octets: p.octets });
    }

    /// `igmp_send_report` d'un message v1 ou v2 (un rapport, un départ) sur
    /// `groupe` : vers le groupe, ou, pour un départ, vers 224.0.0.2.
    fn envoyer_v12(&mut self, genre: u8, groupe: [u8; 4]) {
        if ipv4::multidiffusion_du_lien(groupe) && !RAPPORTS_DU_LIEN {
            return;
        }
        let destination = if genre == DEPART { igmp::TOUS_LES_ROUTEURS } else { groupe };
        let mut o = [0u8; igmp::ENTETE];
        igmp::ecrire(&mut o, genre, groupe);
        if let Ok(octets) = faillible::copie(&o) {
            let _ = self.envois.ajouter(Envoi { interface: self.index, destination, v3: false, octets });
        }
    }
}

/// `grec_size` : la place d'un enregistrement de ce genre, sources
/// comprises (Linux les compte dans les sources du groupe, même pour un
/// enregistrement des sources parties).
fn grec_size(g: &Groupe, genre: u8, gparti: bool, sparti: bool) -> usize {
    let e = Etat { mode: g.mode, comptes: g.comptes, demande: g.demande, crcount: g.crcount };
    igmp::ENREGISTREMENT + 4 * g.sources.iter().filter(|s| is_in(e, s, genre, gparti, sparti)).count()
}

/// `add_grhead` : un enregistrement de plus dans le paquet (un nouveau
/// paquet s'il n'y en a pas), sa place notée dans `enr`.
fn add_grhead(p: Option<Paquet>, groupe: [u8; 4], genre: u8, enr: &mut Option<usize>, mtu: u32) -> Option<Paquet> {
    let mut p = match p {
        Some(p) => p,
        None => Paquet::nouveau(mtu)?,
    };
    *enr = Some(p.octets.len());
    p.mettre(&igmp::enregistrement(genre, groupe));
    igmp::compter_un_enregistrement(&mut p.octets);
    Some(p)
}

/// `add_grec` : ajoute au rapport `p` l'enregistrement de genre `genre` du
/// groupe `g` (`gparti` : un groupe parti, des tombes ; `sparti` : avec ses
/// sources parties, sinon les présentes), avec les sources qu'il doit
/// nommer ; un paquet plein part, et un autre le continue (sauf pour IS_EX
/// et TO_EX, coupés : « truncate these »). Chaque source nommée dans un
/// ALLOW ou un BLOCK a un rapport de moins à faire ; une source partie qui
/// n'en a plus quitte la tombe. Rend le paquet en cours.
fn add_grec(s: &mut Sortie, mut p: Option<Paquet>, g: &mut Groupe, genre: u8, gparti: bool, sparti: bool) -> Option<Paquet> {
    if muet(g.adresse) {
        return p;
    }
    let mtu = (s.h.mtu)(s.index);
    if mtu < MTU_MIN {
        return p;
    }
    let question = genre == EST_INCLURE || genre == EST_EXCLURE;
    let couper = genre == EST_EXCLURE || genre == VERS_EXCLURE;
    let sources_changees = genre == NOUVELLES || genre == ANCIENNES;
    let (mut total, mut n) = (0usize, 0u16);
    let mut enr: Option<usize> = None;
    let vide = if sparti { g.tombe.is_empty() } else { g.sources.is_empty() };
    if !vide {
        // « EX and TO_EX get a fresh packet, if needed »
        if couper && p.as_ref().is_some_and(|q| q.enregistrements() != 0 && q.place() < grec_size(g, genre, gparti, sparti)) {
            if let Some(q) = p.take() {
                s.envoyer(q);
            }
            p = Paquet::nouveau(mtu);
        }
        let e = Etat { mode: g.mode, comptes: g.comptes, demande: g.demande, crcount: g.crcount };
        let liste = if sparti { &mut g.tombe } else { &mut g.sources };
        let mut premier = true;
        let mut k = 0;
        while k < liste.len() {
            if !is_in(e, &liste[k], genre, gparti, sparti) {
                k += 1;
                continue;
            }
            // RFC 3376, 5.1 : pas d'enregistrement de sources avec un
            // changement de mode ; le compte de la source baisse quand même.
            let pendant_le_mode = ((gparti && e.mode == Mode::Exclure) || (!gparti && e.crcount != 0))
                && sources_changees && liste[k].crcount != 0;
            if !pendant_le_mode {
                if question {
                    liste[k].demandee = false;
                }
                if place(&p) < 4 + if premier { igmp::ENREGISTREMENT } else { 0 } {
                    if couper && !premier {
                        break;
                    }
                    if let (Some(q), Some(x)) = (p.as_mut(), enr) {
                        igmp::nombre_de_sources(&mut q.octets, x, n);
                    }
                    if let Some(q) = p.take() {
                        s.envoyer(q);
                    }
                    p = Paquet::nouveau(mtu);
                    premier = true;
                    n = 0;
                }
                if premier {
                    p = add_grhead(p, g.adresse, genre, &mut enr, mtu);
                    premier = false;
                }
                let q = p.as_mut()?;
                q.mettre(&liste[k].adresse);
                n += 1;
                total += 1;
            }
            if sources_changees && liste[k].crcount != 0 {
                liste[k].crcount -= 1;
                if (sparti || gparti) && liste[k].crcount == 0 {
                    liste.remove(k);
                    ranger(liste);
                    continue;
                }
            }
            k += 1;
        }
    }
    if total == 0 {
        if sources_changees {
            return p;
        }
        if g.crcount != 0 || question {
            // « make sure we have room for group header »
            if p.is_some() && place(&p) < igmp::ENREGISTREMENT {
                if let Some(q) = p.take() {
                    s.envoyer(q);
                }
            }
            p = add_grhead(p, g.adresse, genre, &mut enr, mtu);
        }
    }
    if let (Some(q), Some(x)) = (p.as_mut(), enr) {
        igmp::nombre_de_sources(&mut q.octets, x, n);
    }
    if question {
        g.demande = false;
    }
    p
}

/// `igmpv3_clear_zeros` : les sources qui n'ont plus rien à dire s'en vont.
fn clear_zeros(l: &mut Vec<Source>) {
    l.retain(|s| s.crcount != 0);
    ranger(l);
}

/// Après un retrait d'une tombe : vide, sa place est rendue en entier ;
/// sinon, ce qu'elle a en trop (`rendre_la_place`). Une tombe ne vit que le
/// temps de quelques rapports : la place qu'elle garderait vide (4 éléments
/// au moins) serait de la mémoire prise par un programme fini (le contrôle
/// « memoire rendue » du lanceur la verrait).
fn ranger<T>(v: &mut Vec<T>) {
    if v.is_empty() {
        *v = Vec::new();
    } else {
        v.rendre_la_place();
    }
}

impl Interface {
    fn v1(&self, t: u64) -> bool {
        self.v1_vu.is_some_and(|v| t < v)
    }

    fn v2(&self, t: u64) -> bool {
        self.v2_vu.is_some_and(|v| t < v)
    }

    /// Aucun routeur v1 ni v2 entendu depuis le temps qu'il faut
    /// (`IGMP_V1_SEEN`, `IGMP_V2_SEEN`).
    pub(super) fn v3(&self, t: u64) -> bool {
        !self.v1(t) && !self.v2(t)
    }

    /// La version d'IGMP du routeur à l'heure `t` (/proc/net/igmp :
    /// `Querier`).
    pub fn version(&self, t: u64) -> u8 {
        if self.v1(t) {
            1
        } else if self.v2(t) {
            2
        } else {
            3
        }
    }

    /// `unsolicited_report_interval`, en jiffies.
    fn intervalle_non_sollicite(&self, t: u64) -> u32 {
        ms_en_jiffies(if self.v3(t) { NON_SOLLICITE_V3 } else { NON_SOLLICITE_V2 })
    }

    /// `igmp_ifc_event` : un filtre a changé ; en v3, `qrv` rapports de
    /// changement, le premier deux jiffies après.
    pub(super) fn ifc_event(&mut self, c: &Contexte) {
        if !self.v3(c.h.maintenant) {
            return;
        }
        self.ifc_restants = self.qrv;
        self.ifc = Some(au_hasard(c.h, 1));
    }

    /// `igmp_group_added` : un groupe nouveau `k` entre au filtre de la
    /// carte, puis s'annonce. En v1 ou v2 : un rapport bientôt, puis un autre
    /// (`unsolicit_count`) ; en v3 : un rapport de changement (TO_EX pour un
    /// EXCLUDE ; rien pour un INCLUDE sans source, « IN() to IN(A) » : ses
    /// sources le diront).
    pub(super) fn group_added(&mut self, k: usize, c: &Contexte) {
        // Même un groupe qui ne s'annonce pas (224.0.0.1).
        let adresse = self.groupes[k].adresse;
        self.filter_add(adresse);
        let t = c.h.maintenant;
        let v3 = self.v3(t);
        let g = &mut self.groupes[k];
        if muet(g.adresse) {
            return;
        }
        g.non_sollicites = QRV;
        if !v3 {
            g.armer(c.h, DELAI_INITIAL);
            return;
        }
        if g.mode == Mode::Exclure {
            g.crcount = self.qrv;
        }
        self.ifc_event(c);
    }

    /// `__igmp_group_dropped` : le groupe `g` est parti, il quitte le filtre
    /// de la carte. En v1 : rien de plus ; en v2 : un départ si nous avons
    /// fait le dernier rapport ; en v3 : il va dans les tombes
    /// (`igmpv3_add_delrec`), et un rapport de changement le dira.
    pub(super) fn group_dropped(&mut self, mut g: Groupe, c: &mut Contexte) {
        self.filter_del(g.adresse);
        if muet(g.adresse) {
            return;
        }
        let rapporteur = g.rapporteur;
        g.arreter();
        let t = c.h.maintenant;
        if self.v1(t) {
            return;
        }
        if self.v2(t) {
            if rapporteur {
                Sortie { index: self.index, h: c.h, envois: &mut *c.envois }.envoyer_v12(DEPART, g.adresse);
            }
            return;
        }
        self.add_delrec(g);
        self.ifc_event(c);
    }

    /// `igmpv3_add_delrec` : la tombe du groupe parti `g`, en tête : `qrv`
    /// rapports le diront ; en INCLUDE, avec ses sources (chacune pour `qrv`
    /// rapports) et sa tombe. Sans mémoire, rien (comme chez Linux).
    fn add_delrec(&mut self, g: Groupe) {
        let mut t = Groupe::nouveau(g.adresse, g.mode);
        t.utilisateurs = 0;
        t.comptes = [0; 2];
        t.crcount = self.qrv;
        if g.mode == Mode::Inclure {
            t.tombe = g.tombe;
            t.sources = g.sources;
            for s in t.sources.iter_mut() {
                s.crcount = t.crcount;
            }
        }
        let _ = self.tombes.inserer(0, t);
    }

    /// `igmpv3_del_delrec` : le groupe `k`, nouveau, était parti ; ce qui
    /// restait à dire de lui reprend : en INCLUDE, sa tombe et ses sources
    /// d'alors (chacune pour `qrv` rapports) ; en EXCLUDE, son mode.
    pub(super) fn del_delrec(&mut self, k: usize) {
        let adresse = self.groupes[k].adresse;
        let Some(j) = self.tombes.iter().position(|t| t.adresse == adresse) else { return };
        let mut t = self.tombes.remove(j);
        ranger(&mut self.tombes);
        let qrv = self.qrv;
        let g = &mut self.groupes[k];
        if g.mode == Mode::Inclure {
            core::mem::swap(&mut g.tombe, &mut t.tombe);
            core::mem::swap(&mut g.sources, &mut t.sources);
            for s in g.sources.iter_mut() {
                s.crcount = qrv;
            }
        } else {
            g.crcount = qrv;
        }
    }

    /// `igmpv3_clear_delrec` : plus rien à dire de ce qui est parti.
    fn clear_delrec(&mut self) {
        self.tombes = Vec::new();
        for g in self.groupes.iter_mut() {
            g.tombe = Vec::new();
        }
    }

    /// `igmpv3_send_report` : l'état courant (IS_EX ou IS_IN) du groupe `k`,
    /// ou de tous (le plus récent d'abord), en réponse à une requête.
    fn send_report(&mut self, c: &mut Contexte, k: Option<usize>) {
        let mut s = Sortie { index: self.index, h: c.h, envois: &mut *c.envois };
        let mut p = None;
        let groupes = match k {
            Some(k) => &mut self.groupes[k..k + 1],
            None => &mut self.groupes[..],
        };
        for g in groupes.iter_mut().rev() {
            if muet(g.adresse) {
                continue;
            }
            let genre = if g.comptes[Mode::Exclure as usize] != 0 { EST_EXCLURE } else { EST_INCLURE };
            p = add_grec(&mut s, p, g, genre, false, false);
        }
        if let Some(p) = p {
            s.envoyer(p);
        }
    }

    /// `igmpv3_send_cr` : le rapport de changement. Les groupes partis
    /// d'abord (BLOCK des sources d'un INCLUDE, TO_IN {} d'un EXCLUDE), qui
    /// quittent les tombes quand tout est dit ; puis chaque groupe : les
    /// sources qui entrent ou sortent, et son mode s'il a changé.
    fn send_cr(&mut self, c: &mut Contexte) {
        let mut s = Sortie { index: self.index, h: c.h, envois: &mut *c.envois };
        let mut p = None;
        let mut k = 0;
        while k < self.tombes.len() {
            let t = &mut self.tombes[k];
            if t.mode == Mode::Inclure {
                p = add_grec(&mut s, p, t, ANCIENNES, true, false);
                p = add_grec(&mut s, p, t, ANCIENNES, true, true);
            }
            if t.crcount != 0 {
                if t.mode == Mode::Exclure {
                    p = add_grec(&mut s, p, t, VERS_INCLURE, true, false);
                }
                t.crcount -= 1;
                if t.crcount == 0 {
                    clear_zeros(&mut t.tombe);
                    clear_zeros(&mut t.sources);
                }
            }
            if t.crcount == 0 && t.tombe.is_empty() && t.sources.is_empty() {
                self.tombes.remove(k);
                ranger(&mut self.tombes);
            } else {
                k += 1;
            }
        }
        for g in self.groupes.iter_mut().rev() {
            let (genre, dgenre) =
                if g.comptes[Mode::Exclure as usize] != 0 { (ANCIENNES, NOUVELLES) } else { (NOUVELLES, ANCIENNES) };
            p = add_grec(&mut s, p, g, genre, false, false);
            p = add_grec(&mut s, p, g, dgenre, false, true);
            if g.crcount != 0 {
                let genre = if g.mode == Mode::Exclure { VERS_EXCLURE } else { VERS_INCLURE };
                p = add_grec(&mut s, p, g, genre, false, false);
                g.crcount -= 1;
            }
        }
        if let Some(p) = p {
            s.envoyer(p);
        }
    }

    /// La prochaine échéance de l'interface.
    fn prochaine(&self) -> Option<u64> {
        self.groupes.iter().filter_map(|g| g.minuteur).chain(self.ifc).chain(self.gq).min()
    }

    /// Fait le premier minuteur échu, s'il y en a un : faux sinon.
    fn echoir(&mut self, c: &mut Contexte) -> bool {
        let t = c.h.maintenant;
        let Some(e) = self.prochaine().filter(|&e| e <= t) else { return false };
        if self.ifc == Some(e) {
            // `igmp_ifc_timer_expire`
            self.ifc = None;
            self.send_cr(c);
            if self.ifc_restants != 0 {
                self.ifc_restants -= 1;
                self.ifc = Some(au_hasard(c.h, self.intervalle_non_sollicite(t)));
            }
        } else if self.gq == Some(e) {
            // `igmp_gq_timer_expire`
            self.gq = None;
            self.send_report(c, None);
        } else if let Some(k) = self.groupes.iter().position(|g| g.minuteur == Some(e)) {
            self.timer_expire(k, c);
        }
        true
    }

    /// `igmp_timer_expire` : le minuteur du groupe `k` est échu : un rapport
    /// de la version du routeur, et le suivant s'il en reste à faire
    /// (`unsolicit_count`) ; ce rapport-là vient de nous.
    fn timer_expire(&mut self, k: usize, c: &mut Contexte) {
        let t = c.h.maintenant;
        let intervalle = self.intervalle_non_sollicite(t);
        let g = &mut self.groupes[k];
        g.minuteur = None;
        if g.non_sollicites != 0 {
            g.non_sollicites -= 1;
            if g.non_sollicites != 0 {
                g.armer(c.h, intervalle);
            }
        }
        g.rapporteur = true;
        let adresse = g.adresse;
        if self.v1(t) {
            Sortie { index: self.index, h: c.h, envois: &mut *c.envois }.envoyer_v12(RAPPORT_V1, adresse);
        } else if self.v2(t) {
            Sortie { index: self.index, h: c.h, envois: &mut *c.envois }.envoyer_v12(RAPPORT_V2, adresse);
        } else {
            self.send_report(c, Some(k));
        }
    }

    /// `igmp_heard_report` : une autre machine a fait le rapport sur
    /// `groupe` ; le nôtre est inutile (RFC 2236, 3 : « suppression »).
    fn heard_report(&mut self, groupe: [u8; 4]) {
        if muet(groupe) {
            return;
        }
        if let Some(g) = self.groupes.iter_mut().rev().find(|g| g.adresse == groupe) {
            g.arreter();
        }
    }

    /// `igmp_heard_query` : une requête (`m`, son message entier `o`). 8
    /// octets : v1 (code 0) ou v2, dont le routeur est noté pour `qrv × qi +
    /// qri`, et les rapports v3 en attente oubliés ; moins de 12 : jetée ;
    /// sinon v3, lue comme v1 ou v2 si un tel routeur est noté. Une requête
    /// générale v3 : un rapport de tout, au hasard dans son délai ; sinon,
    /// le minuteur de chaque groupe qu'elle vise (tous, ou le sien), sauf
    /// 224.0.0.1.
    fn heard_query(&mut self, c: &Contexte, m: Igmp, o: &[u8]) {
        let t = c.h.maintenant;
        let mut groupe = m.groupe;
        let mut marque = false;
        let mut requete = None;
        let delai = if o.len() == igmp::ENTETE {
            let vu = Some(t + self.qrv as u64 * self.qi + self.qri);
            let delai = if m.code == 0 {
                // « Alas, old v1 router presents here. »
                self.v1_vu = vu;
                groupe = ipv4::AUCUNE;
                (DELAI_DE_REPONSE / JIFFY) as u32
            } else {
                self.v2_vu = vu;
                m.code as u32 * (HZ / 10) as u32
            };
            self.ifc_restants = 0;
            self.ifc = None;
            self.clear_delrec();
            delai
        } else if o.len() < igmp::REQUETE_V3 {
            return;
        } else if self.v1(t) {
            groupe = ipv4::AUCUNE;
            (DELAI_DE_REPONSE / JIFFY) as u32
        } else if self.v2(t) {
            // Le délai codé comme en v3 (« more likely to be intended in a
            // v3 query »).
            (igmp::duree(m.code) * (HZ / 10) as u32).max(1)
        } else {
            let Ok(r) = igmp::lire_requete_v3(o) else { return };
            let delai = (igmp::duree(m.code) * (HZ / 10) as u32).max(1);
            self.delai_max = delai;
            // RFC 3376, 4.1.6 et 4.1.7 : 0, la valeur par défaut.
            self.qrv = if r.qrv != 0 { r.qrv } else { QRV };
            self.qi = match igmp::duree(r.qqic) as u64 * SECONDE {
                0 => INTERVALLE_DES_REQUETES,
                qi => qi,
            };
            // RFC 3376, 8.3 : le délai de réponse est plus court que
            // l'intervalle des requêtes.
            if self.qri >= self.qi {
                self.qri = (self.qi / SECONDE).saturating_sub(1) * SECONDE;
            }
            if groupe == ipv4::AUCUNE {
                // Une requête générale : « no sources allowed ».
                if r.nombre() != 0 {
                    return;
                }
                // `igmp_gq_start_timer`
                let e = au_hasard(c.h, self.delai_max);
                if self.gq.is_none_or(|x| e < x) {
                    self.gq = Some(e);
                }
                return;
            }
            marque = r.nombre() != 0;
            requete = Some(r);
            delai
        };
        for g in self.groupes.iter_mut().rev() {
            if (groupe != ipv4::AUCUNE && groupe != g.adresse) || muet(g.adresse) {
                continue;
            }
            g.demande = if g.minuteur.is_some() { g.demande && marque } else { marque };
            let change = !g.demande || requete.as_ref().is_some_and(|r| g.marksources(r));
            if change {
                g.rearmer(c.h, delai);
            }
        }
    }

    /// `igmp_rcv` : un message IGMP arrivé par cette interface (`o` : tout
    /// ce que porte le paquet). `de_nous` : notre propre rapport, rendu par
    /// la boucle (`rt_is_output_route`) ; `diffuse` : arrivé dans une trame
    /// pour plusieurs machines (PACKET_MULTICAST ou PACKET_BROADCAST). Une
    /// requête est entendue ; le rapport v1 ou v2 d'une autre machine aussi ;
    /// le reste (un rapport v3, un départ : pour les routeurs) ignoré.
    fn recevoir(&mut self, c: &Contexte, o: &[u8], de_nous: bool, diffuse: bool) {
        let Ok(m) = igmp::lire(o) else { return };
        match m.genre {
            REQUETE => self.heard_query(c, m, o),
            RAPPORT_V1 | RAPPORT_V2 if !de_nous && diffuse => self.heard_report(m.groupe),
            _ => {}
        }
    }
}

impl Groupes {
    /// Les rapports prêts à partir, pris : le noyau les envoie, son verrou
    /// lâché.
    pub fn prendre_les_envois(&mut self) -> Vec<Envoi> {
        core::mem::take(&mut self.envois)
    }

    /// La prochaine échéance de toutes les interfaces.
    pub fn prochaine_echeance(&self) -> Option<u64> {
        self.interfaces.iter().filter_map(Interface::prochaine).min()
    }

    /// Fait ce qui est échu à l'heure réglée, dans l'ordre des échéances de
    /// chaque interface.
    pub fn temps(&mut self) {
        let h = self.horloge;
        for i in self.interfaces.iter_mut() {
            let mut c = Contexte { h, envois: &mut self.envois };
            while i.echoir(&mut c) {}
        }
    }

    /// Un message IGMP arrivé par l'interface `index` (`igmp_rcv`).
    pub fn recevoir(&mut self, index: u32, o: &[u8], de_nous: bool, diffuse: bool) {
        if let Some((i, c)) = self.interface_mut(index) {
            i.recevoir(&c, o, de_nous, diffuse);
        }
    }
}
