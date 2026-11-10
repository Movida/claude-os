//! L'en-tête d'IPv4 (RFC 791) : 20 octets, plus des options (jusqu'à 40) :
//! la version (4), la longueur de l'en-tête en mots de 32 bits (IHL), le
//! type de service, la longueur totale du paquet, l'identifiant et les
//! drapeaux de fragmentation, la durée de vie (TTL), le protocole de ce qui
//! suit (1 ICMP, 6 TCP, 17 UDP), la somme de contrôle de l'en-tête, et les
//! adresses de la source et de la destination. Les options d'un paquet
//! reçu se vérifient comme chez Linux (`compiler_options`) ; nous n'en
//! écrivons pas.

use super::{Erreur, adresse, mot16, plier, somme};

/// La taille de l'en-tête sans options (le seul que nous écrivons).
pub const ENTETE: usize = 20;
/// Les protocoles.
pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
/// L'adresse de diffusion limitée : tout le réseau local.
pub const DIFFUSION: [u8; 4] = [255; 4];
/// L'adresse « pas encore d'adresse » (la source d'un DHCP DISCOVER).
pub const AUCUNE: [u8; 4] = [0; 4];

/// Les bits de drapeaux du mot de fragmentation.
const NE_PAS_FRAGMENTER: u16 = 0x4000;
const FRAGMENTS_SUIVANTS: u16 = 0x2000;
const DECALAGE: u16 = 0x1FFF;

/// Un en-tête IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4 {
    pub tos: u8,
    /// La longueur de tout le paquet, en-tête compris.
    pub longueur: u16,
    pub identifiant: u16,
    /// DF : le paquet ne doit pas être fragmenté en chemin.
    pub ne_pas_fragmenter: bool,
    /// MF : d'autres fragments suivent.
    pub fragments_suivants: bool,
    /// La place du fragment dans le paquet d'origine, en unités de 8 octets.
    pub decalage: u16,
    pub ttl: u8,
    pub protocole: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    /// La longueur de l'en-tête, options comprises.
    pub longueur_entete: usize,
}

impl Ipv4 {
    /// Est-ce un fragment (un morceau d'un paquet plus grand) ?
    pub fn est_un_fragment(&self) -> bool {
        self.fragments_suivants || self.decalage != 0
    }
}

/// Lit l'en-tête au début de `o`, et rend sa charge (de la fin de l'en-tête
/// à la longueur totale : le bourrage d'Ethernet au-delà est ôté). Les
/// vérifications dans l'ordre d'`ip_rcv_core` : 20 octets au moins, la
/// version 4 et une longueur d'en-tête d'au moins 5 mots, l'en-tête entier
/// présent, sa somme, puis une longueur totale qui tient dans ce qui a été
/// reçu et couvre l'en-tête.
pub fn lire(o: &[u8]) -> Result<(Ipv4, &[u8]), Erreur> {
    let h = entete(o, true)?;
    if (h.longueur as usize) > o.len() {
        return Err(Erreur::Tronque);
    }
    Ok((h, &o[h.longueur_entete..h.longueur as usize]))
}

/// L'en-tête d'un paquet qu'on cite dans une erreur ICMP qu'on va envoyer
/// (`__icmp_send` ne le relit pas en entier, ni sa somme) : les mêmes
/// vérifications que `lire`, sauf la longueur totale, qui peut dépasser ce
/// qu'on a (une longueur plus courte que l'en-tête reste refusée), et la
/// somme : elle était juste à l'arrivée, mais la lecture des options a pu
/// changer l'en-tête depuis sans la refaire (`compiler_options`), comme
/// chez Linux.
pub fn lire_cite(o: &[u8]) -> Result<Ipv4, Erreur> {
    entete(o, false)
}

/// L'en-tête au début de `o`, dans l'ordre d'`ip_rcv_core` ; sa somme
/// vérifiée si `somme_verifiee`.
fn entete(o: &[u8], somme_verifiee: bool) -> Result<Ipv4, Erreur> {
    let debut = o.get(..ENTETE).ok_or(Erreur::Tronque)?;
    let ihl = (debut[0] & 0x0F) as usize;
    if debut[0] >> 4 != 4 || ihl < 5 {
        return Err(Erreur::Invalide);
    }
    let longueur_entete = ihl * 4;
    let entete = o.get(..longueur_entete).ok_or(Erreur::Tronque)?;
    if somme_verifiee && plier(somme(entete, 0)) != 0 {
        return Err(Erreur::Somme);
    }
    let longueur = mot16(entete, 2).ok_or(Erreur::Tronque)?;
    if (longueur as usize) < longueur_entete {
        return Err(Erreur::Invalide);
    }
    let fragment = mot16(entete, 6).ok_or(Erreur::Tronque)?;
    Ok(Ipv4 {
        tos: entete[1],
        longueur,
        identifiant: mot16(entete, 4).ok_or(Erreur::Tronque)?,
        ne_pas_fragmenter: fragment & NE_PAS_FRAGMENTER != 0,
        fragments_suivants: fragment & FRAGMENTS_SUIVANTS != 0,
        decalage: fragment & DECALAGE,
        ttl: entete[8],
        protocole: entete[9],
        source: adresse(entete, 12).ok_or(Erreur::Tronque)?,
        destination: adresse(entete, 16).ok_or(Erreur::Tronque)?,
        longueur_entete,
    })
}

/// Un paquet recollé : l'en-tête `o` (celui de son premier fragment, options comprises,
/// `ip_frag_reasm`) dit sa longueur totale, plus de fragment, et les bits ECN réunis ;
/// sa somme refaite.
pub fn finir_recollage(o: &mut [u8], longueur: u16, ecn: u8) {
    o[1] |= ecn;
    o[2..4].copy_from_slice(&longueur.to_be_bytes());
    o[6..8].fill(0);
    o[10..12].fill(0);
    let s = plier(somme(o, 0));
    o[10..12].copy_from_slice(&s.to_be_bytes());
}

/// Écrit l'en-tête `h` (sans options : `longueur_entete` est ignoré) dans
/// les 20 premiers octets de `o`, sa somme comprise.
pub fn ecrire(o: &mut [u8; ENTETE], h: &Ipv4) {
    o[0] = 0x45;
    o[1] = h.tos;
    o[2..4].copy_from_slice(&h.longueur.to_be_bytes());
    o[4..6].copy_from_slice(&h.identifiant.to_be_bytes());
    let fragment = (h.decalage & DECALAGE)
        | if h.ne_pas_fragmenter { NE_PAS_FRAGMENTER } else { 0 }
        | if h.fragments_suivants { FRAGMENTS_SUIVANTS } else { 0 };
    o[6..8].copy_from_slice(&fragment.to_be_bytes());
    o[8] = h.ttl;
    o[9] = h.protocole;
    o[10..12].fill(0);
    o[12..16].copy_from_slice(&h.source);
    o[16..20].copy_from_slice(&h.destination);
    let s = plier(somme(o, 0));
    o[10..12].copy_from_slice(&s.to_be_bytes());
}

/// Une adresse de multidiffusion (224.0.0.0/4, la « classe D »).
pub fn multidiffusion(a: [u8; 4]) -> bool {
    a[0] & 0xF0 == 0xE0
}

/// Une adresse de la boucle locale (127.0.0.0/8).
pub fn boucle(a: [u8; 4]) -> bool {
    a[0] == 127
}

/// Le masque d'un préfixe de `bits` bits (24 : 255.255.255.0).
pub fn masque(bits: u8) -> [u8; 4] {
    let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits.min(32) as u32) };
    m.to_be_bytes()
}

/// La longueur du préfixe d'un masque (255.255.255.0 : 24), s'il est fait
/// de 1 puis de 0.
pub fn prefixe(masque: [u8; 4]) -> Option<u8> {
    let m = u32::from_be_bytes(masque);
    let bits = m.leading_ones();
    (m.checked_shl(bits).unwrap_or(0) == 0).then_some(bits as u8)
}

/// `a` est-elle dans le réseau `reseau`/`bits` ?
pub fn dans(a: [u8; 4], reseau: [u8; 4], bits: u8) -> bool {
    let m = u32::from_be_bytes(masque(bits));
    u32::from_be_bytes(a) & m == u32::from_be_bytes(reseau) & m
}

/// Les genres d'options (RFC 791 et suivantes), comme Linux les nomme
/// (`IPOPT_*`).
pub mod option {
    pub const FIN: u8 = 0;
    pub const BOURRAGE: u8 = 1;
    /// La route notée (« record route ») : chaque machine y écrit son adresse.
    pub const ROUTE_NOTEE: u8 = 7;
    /// L'horodatage : chaque machine y écrit l'heure (et son adresse).
    pub const HORODATAGE: u8 = 68;
    pub const SECURITE: u8 = 130;
    /// Les routes sources : lâche (LSRR) et stricte (SSRR).
    pub const ROUTE_SOURCE_LACHE: u8 = 131;
    pub const CIPSO: u8 = 134;
    pub const FLUX: u8 = 136;
    pub const ROUTE_SOURCE_STRICTE: u8 = 137;
    /// L'alerte aux routeurs (RFC 2113).
    pub const ALERTE: u8 = 148;
    /// Les drapeaux de l'horodatage : l'heure seule, l'heure et l'adresse,
    /// l'heure aux adresses données d'avance.
    pub const HEURE_SEULE: u8 = 0;
    pub const HEURE_ET_ADRESSE: u8 = 1;
    pub const ADRESSES_DONNEES: u8 = 3;
}

/// Ce que disent les options d'un paquet reçu, une fois vérifiées (le
/// `struct ip_options` de Linux) : la place de chacune dans l'en-tête,
/// comptée depuis son premier octet (0 : absente).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    pub route_source: u8,
    /// La route source est stricte (SSRR).
    pub stricte: bool,
    pub route_notee: u8,
    pub horodatage: u8,
    pub alerte: u8,
    /// Des octets de l'en-tête ont changé (`is_changed`).
    pub modifiees: bool,
}

/// Ce que le paquet reçu laisse dans ses options, comme Linux : son
/// adresse pour nous joindre (`spec_dst`, celle qu'écrivent la route notée
/// et l'horodatage avec adresse), l'heure (`inet_current_timestamp` : les
/// millisecondes depuis minuit, temps universel), et ce qui dit si une
/// adresse donnée d'avance est quelqu'un d'autre (`inet_addr_type` ==
/// RTN_UNICAST : ni à nous, ni une diffusion, ni une multidiffusion).
pub struct Ici<'a> {
    pub adresse: [u8; 4],
    pub heure: u32,
    pub unicast: &'a dyn Fn([u8; 4]) -> bool,
}

/// Les options de l'en-tête reçu `entete` (en entier, ses 20 premiers
/// octets compris), vérifiées une à une et complétées sur place comme
/// `__ip_options_compile` de Linux (net/ipv4/ip_options.c) pour un paquet
/// reçu. Une option fausse : `Err(place)`, l'octet fautif compté depuis le
/// début de l'en-tête, que dira le « problème de paramètre » (ICMP 12) ;
/// le paquet est jeté.
///
/// Les règles, option par option :
/// - la fin (0) : tout ce qui la suit devient 0 ; le bourrage (1) : un
///   octet ;
/// - les autres : un octet de genre, un de longueur (au moins 2, et pas
///   plus que ce qui reste), puis leur contenu ;
/// - les routes sources : au moins 3 octets, le pointeur (le troisième) à
///   4 au moins, une seule par paquet (la RFC 1812, 5.2.4.1) ;
/// - la route notée : une seule ; au moins 3 octets, pointeur à 4 au
///   moins ; s'il reste la place d'une adresse, la nôtre y est écrite et le
///   pointeur avance de 4 ;
/// - l'horodatage : un seul ; au moins 4 octets, pointeur à 5 au moins ;
///   s'il reste de la place : l'heure (drapeau 0), l'adresse et l'heure
///   (1), l'heure si l'adresse donnée d'avance n'est pas quelqu'un d'autre
///   (3) ; un autre drapeau est accepté tel quel. Sans place : le compteur
///   de débordement (les 4 bits forts du quatrième octet) augmente ; à 15,
///   c'est une erreur ;
/// - l'alerte aux routeurs : au moins 4 octets ; notée si sa valeur est 0 ;
/// - CIPSO (une étiquette de sécurité) : jamais acceptée, faute de domaine
///   connu (Linux n'en a aucun tant que netlabelctl n'en définit pas :
///   `cipso_v4_validate` refuse alors le troisième octet, le début du
///   domaine, ou le deuxième, la longueur, si l'option a moins de 8
///   octets) ;
/// - les autres (sécurité, identifiant de flux, inconnues) : acceptées
///   telles quelles (Linux ne les refuse qu'à l'envoi, sans CAP_NET_RAW).
///
/// La somme de l'en-tête n'est pas refaite : Linux ne la refait que pour
/// un paquet qu'il fait suivre, et une erreur ICMP en recopie l'en-tête
/// tel qu'il est alors (options notées, ancienne somme).
pub fn compiler_options(entete: &mut [u8], ici: &Ici) -> Result<Options, u8> {
    use option::*;
    let mut opt = Options::default();
    let mut k = ENTETE;
    let fin = entete.len();
    // Une place dans l'en-tête, comme Linux la rend dans `info`.
    let place = |k: usize| k as u8;
    while k < fin {
        match entete[k] {
            FIN => {
                for o in &mut entete[k + 1..] {
                    if *o != FIN {
                        *o = FIN;
                        opt.modifiees = true;
                    }
                }
                return Ok(opt);
            }
            BOURRAGE => {
                k += 1;
                continue;
            }
            _ => {}
        }
        let reste = fin - k;
        if reste < 2 {
            return Err(place(k));
        }
        let longueur = entete[k + 1] as usize;
        if longueur < 2 || longueur > reste {
            return Err(place(k));
        }
        let o = &mut entete[k..k + longueur];
        match o[0] {
            ROUTE_SOURCE_LACHE | ROUTE_SOURCE_STRICTE => {
                if longueur < 3 {
                    return Err(place(k + 1));
                }
                if o[2] < 4 {
                    return Err(place(k + 2));
                }
                if opt.route_source != 0 {
                    return Err(place(k));
                }
                opt.stricte = o[0] == ROUTE_SOURCE_STRICTE;
                opt.route_source = place(k);
            }
            ROUTE_NOTEE => {
                if opt.route_notee != 0 {
                    return Err(place(k));
                }
                if longueur < 3 {
                    return Err(place(k + 1));
                }
                let pointeur = o[2] as usize;
                if pointeur < 4 {
                    return Err(place(k + 2));
                }
                if pointeur <= longueur {
                    if pointeur + 3 > longueur {
                        return Err(place(k + 2));
                    }
                    o[pointeur - 1..pointeur + 3].copy_from_slice(&ici.adresse);
                    o[2] += 4;
                    opt.modifiees = true;
                }
                opt.route_notee = place(k);
            }
            HORODATAGE => {
                if opt.horodatage != 0 {
                    return Err(place(k));
                }
                if longueur < 4 {
                    return Err(place(k + 1));
                }
                let pointeur = o[2] as usize;
                if pointeur < 5 {
                    return Err(place(k + 2));
                }
                let drapeau = o[3] & 0xF;
                if pointeur <= longueur {
                    if pointeur + 3 > longueur {
                        return Err(place(k + 2));
                    }
                    // Où écrire l'heure, s'il le faut.
                    let heure = match drapeau {
                        HEURE_SEULE => {
                            o[2] += 4;
                            Some(pointeur - 1)
                        }
                        HEURE_ET_ADRESSE | ADRESSES_DONNEES => {
                            if pointeur + 7 > longueur {
                                return Err(place(k + 2));
                            }
                            let a = [o[pointeur - 1], o[pointeur], o[pointeur + 1], o[pointeur + 2]];
                            if drapeau == ADRESSES_DONNEES && (ici.unicast)(a) {
                                None
                            } else {
                                if drapeau == HEURE_ET_ADRESSE {
                                    o[pointeur - 1..pointeur + 3].copy_from_slice(&ici.adresse);
                                }
                                o[2] += 8;
                                Some(pointeur + 3)
                            }
                        }
                        _ => None,
                    };
                    if let Some(h) = heure {
                        o[h..h + 4].copy_from_slice(&ici.heure.to_be_bytes());
                        opt.modifiees = true;
                    }
                } else if drapeau != ADRESSES_DONNEES {
                    let debordement = o[3] >> 4;
                    if debordement == 15 {
                        return Err(place(k + 3));
                    }
                    o[3] = drapeau | ((debordement + 1) << 4);
                    opt.modifiees = true;
                }
                opt.horodatage = place(k);
            }
            ALERTE => {
                if longueur < 4 {
                    return Err(place(k + 1));
                }
                if o[2] == 0 && o[3] == 0 {
                    opt.alerte = place(k);
                }
            }
            CIPSO => return Err(place(if longueur < 8 { k + 1 } else { k + 2 })),
            _ => {}
        }
        k += longueur;
    }
    Ok(opt)
}
