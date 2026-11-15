//! Les messages d'IGMP (RFC 1112, 2236 et 3376) : comment une machine dit
//! aux routeurs de son lien à quels groupes de multidiffusion elle adhère,
//! et comment ils le lui demandent. Un routeur (le « querier ») envoie de
//! temps en temps une requête à 224.0.0.1 ; chaque machine répond par un
//! rapport, après un délai au hasard ; et elle en envoie un sans qu'on le
//! lui demande quand ses adhésions changent.
//!
//! Trois versions, qui se reconnaissent à la requête du routeur : v1 (RFC
//! 1112 : 8 octets, code 0), v2 (RFC 2236 : 8 octets, le délai de réponse
//! dans le code), v3 (RFC 3376 : 12 octets au moins, avec les sources). Un
//! rapport v1 ou v2 fait 8 octets et va au groupe lui-même ; un rapport v3
//! va à 224.0.0.22 (tous les routeurs v3), et porte des enregistrements :
//! pour un groupe, un genre (l'état d'un filtre, un changement de filtre,
//! des sources nouvelles ou anciennes) et des sources.
//!
//! L'en-tête commun : le genre, le code, une somme de contrôle sur tout le
//! message, le groupe. Lu ici (la longueur bornée par ce qui a été reçu,
//! comme chaque en-tête de `formats::reseau`), écrit ici.

use super::{Erreur, adresse, mot16, plier, somme};

/// La taille de l'en-tête commun, et d'un message v1 ou v2.
pub const ENTETE: usize = 8;
/// La taille d'une requête v3 sans ses sources (`struct igmpv3_query`).
pub const REQUETE_V3: usize = 12;
/// La taille de l'en-tête d'un rapport v3 (`struct igmpv3_report`) : le
/// genre, un octet nul, la somme, deux octets nuls, le nombre
/// d'enregistrements.
pub const ENTETE_V3: usize = 8;
/// La taille d'un enregistrement de rapport v3 sans ses sources (`struct
/// igmpv3_grec`) : son genre, la longueur de ses données auxiliaires (0),
/// son nombre de sources, le groupe.
pub const ENREGISTREMENT: usize = 8;

// Les genres de messages.
/// Une requête du routeur (les trois versions).
pub const REQUETE: u8 = 0x11;
pub const RAPPORT_V1: u8 = 0x12;
pub const RAPPORT_V2: u8 = 0x16;
/// Un départ (v2) : la machine quitte le groupe.
pub const DEPART: u8 = 0x17;
pub const RAPPORT_V3: u8 = 0x22;

// Les genres d'enregistrements d'un rapport v3 (RFC 3376, 4.2.12).
/// L'état courant, en réponse à une requête : le filtre est INCLUDE de ces
/// sources (MODE_IS_INCLUDE), ou EXCLUDE de celles-ci (MODE_IS_EXCLUDE).
pub const EST_INCLURE: u8 = 1;
pub const EST_EXCLURE: u8 = 2;
/// Le filtre change de mode (CHANGE_TO_INCLUDE, CHANGE_TO_EXCLUDE).
pub const VERS_INCLURE: u8 = 3;
pub const VERS_EXCLURE: u8 = 4;
/// Des sources entrent (ALLOW_NEW_SOURCES), ou sortent
/// (BLOCK_OLD_SOURCES).
pub const NOUVELLES: u8 = 5;
pub const ANCIENNES: u8 = 6;

/// 224.0.0.2 : tous les routeurs, où va un départ v2.
pub const TOUS_LES_ROUTEURS: [u8; 4] = [224, 0, 0, 2];
/// 224.0.0.22 : les routeurs d'IGMPv3, où vont ses rapports.
pub const ROUTEURS_V3: [u8; 4] = [224, 0, 0, 22];

/// L'en-tête commun d'un message reçu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Igmp {
    pub genre: u8,
    /// Le délai de réponse d'une requête v2 (en dixièmes de seconde), ou
    /// celui d'une v3 (`duree`) ; 0 ailleurs.
    pub code: u8,
    pub groupe: [u8; 4],
}

/// Lit l'en-tête du message `o` (tout ce que porte le paquet IP) : au moins
/// 8 octets, une somme juste sur le tout (`igmp_rcv` : `pskb_may_pull` de
/// l'en-tête, puis `skb_checksum_simple_validate`).
pub fn lire(o: &[u8]) -> Result<Igmp, Erreur> {
    if o.len() < ENTETE {
        return Err(Erreur::Tronque);
    }
    if plier(somme(o, 0)) != 0 {
        return Err(Erreur::Somme);
    }
    Ok(Igmp { genre: o[0], code: o[1], groupe: adresse(o, 4).ok_or(Erreur::Tronque)? })
}

/// Ce qu'ajoute une requête v3 à l'en-tête commun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequeteV3<'a> {
    /// « Robustness Variable » : combien de fois répéter un rapport (3 bits ;
    /// 0 : la valeur par défaut).
    pub qrv: u8,
    /// « Querier's Query Interval Code » : l'intervalle entre deux requêtes
    /// du routeur, codé comme un délai (`duree`), en secondes.
    pub qqic: u8,
    /// Les sources, 4 octets chacune.
    sources: &'a [u8],
}

impl RequeteV3<'_> {
    pub fn nombre(&self) -> usize {
        self.sources.len() / 4
    }

    pub fn sources(&self) -> impl Iterator<Item = [u8; 4]> + '_ {
        self.sources.chunks_exact(4).map(|s| [s[0], s[1], s[2], s[3]])
    }
}

/// Lit la suite d'une requête v3 (`o` : tout le message, déjà passé par
/// `lire`) : 12 octets au moins, puis toutes les sources qu'elle annonce
/// (Linux jette la requête sinon).
pub fn lire_requete_v3(o: &[u8]) -> Result<RequeteV3<'_>, Erreur> {
    if o.len() < REQUETE_V3 {
        return Err(Erreur::Tronque);
    }
    let n = mot16(o, 10).ok_or(Erreur::Tronque)? as usize;
    let sources = o.get(REQUETE_V3..REQUETE_V3 + 4 * n).ok_or(Erreur::Tronque)?;
    Ok(RequeteV3 { qrv: o[8] & 7, qqic: o[9], sources })
}

/// Un délai codé sur un octet (RFC 3376, 4.1.1 et 4.1.7 : `IGMPV3_MRC` et
/// `IGMPV3_QQIC`) : tel quel sous 128 ; au-delà, une mantisse de 4 bits (un
/// 1 devant) décalée de l'exposant (3 bits) plus 3. En dixièmes de seconde
/// pour le délai de réponse, en secondes pour l'intervalle des requêtes.
pub fn duree(code: u8) -> u32 {
    if code < 0x80 {
        return code as u32;
    }
    (((code & 0x0f) | 0x10) as u32) << (((code >> 4) & 7) + 3)
}

/// Écrit dans `o` un message v1 ou v2 (un rapport, un départ) pour
/// `groupe`, code 0, sa somme comprise (`igmp_send_report`).
pub fn ecrire(o: &mut [u8; ENTETE], genre: u8, groupe: [u8; 4]) {
    o[0] = genre;
    o[1] = 0;
    o[2..4].copy_from_slice(&[0, 0]);
    o[4..8].copy_from_slice(&groupe);
    sceller(o);
}

/// L'en-tête d'un rapport v3 sans enregistrement, sa somme à faire
/// (`igmpv3_newpack`).
pub const RAPPORT_V3_VIDE: [u8; ENTETE_V3] = [RAPPORT_V3, 0, 0, 0, 0, 0, 0, 0];

/// L'en-tête d'un enregistrement de genre `genre` pour `groupe`, sans
/// source (`add_grhead`) : `nombre_de_sources` l'écrit à la fin.
pub fn enregistrement(genre: u8, groupe: [u8; 4]) -> [u8; ENREGISTREMENT] {
    [genre, 0, 0, 0, groupe[0], groupe[1], groupe[2], groupe[3]]
}

/// Écrit le nombre de sources `n` de l'enregistrement qui commence à
/// `debut` dans le rapport `o`.
pub fn nombre_de_sources(o: &mut [u8], debut: usize, n: u16) {
    o[debut + 2..debut + 4].copy_from_slice(&n.to_be_bytes());
}

/// Ajoute un enregistrement au compte du rapport v3 `o` (`ngrec`).
pub fn compter_un_enregistrement(o: &mut [u8]) {
    let n = u16::from_be_bytes([o[6], o[7]]).wrapping_add(1);
    o[6..8].copy_from_slice(&n.to_be_bytes());
}

/// Pose la somme de contrôle du message `o`, qui couvre tout le message
/// (`ip_compute_csum`).
pub fn sceller(o: &mut [u8]) {
    o[2..4].copy_from_slice(&[0, 0]);
    let s = plier(somme(o, 0));
    o[2..4].copy_from_slice(&s.to_be_bytes());
}

/// Un enregistrement d'un rapport v3 reçu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enregistrement<'a> {
    pub genre: u8,
    pub groupe: [u8; 4],
    sources: &'a [u8],
}

impl Enregistrement<'_> {
    pub fn sources(&self) -> impl Iterator<Item = [u8; 4]> + '_ {
        self.sources.chunks_exact(4).map(|s| [s[0], s[1], s[2], s[3]])
    }
}

/// Les enregistrements du rapport v3 `o` (passé par `lire`, de genre
/// RAPPORT_V3), dans l'ordre ; un enregistrement qui dépasse du message :
/// Tronque. Pour les tests : notre noyau ignore les rapports v3 qu'il
/// entend (il n'est pas un routeur).
pub fn enregistrements(o: &[u8]) -> Result<impl Iterator<Item = Enregistrement<'_>>, Erreur> {
    let n = mot16(o, 6).ok_or(Erreur::Tronque)? as usize;
    let mut k = ENTETE_V3;
    let mut bornes = [(0usize, 0usize); 64];
    if n > bornes.len() {
        return Err(Erreur::Invalide);
    }
    for b in bornes.iter_mut().take(n) {
        let auxiliaires = *o.get(k + 1).ok_or(Erreur::Tronque)? as usize * 4;
        let sources = mot16(o, k + 2).ok_or(Erreur::Tronque)? as usize;
        let fin = k + ENREGISTREMENT + 4 * sources + auxiliaires;
        if fin > o.len() {
            return Err(Erreur::Tronque);
        }
        *b = (k, sources);
        k = fin;
    }
    Ok(bornes.into_iter().take(n).map(move |(k, sources)| Enregistrement {
        genre: o[k],
        groupe: [o[k + 4], o[k + 5], o[k + 6], o[k + 7]],
        sources: &o[k + ENREGISTREMENT..k + ENREGISTREMENT + 4 * sources],
    }))
}
