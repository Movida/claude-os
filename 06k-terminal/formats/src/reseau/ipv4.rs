//! L'en-tête d'IPv4 (RFC 791) : 20 octets, plus des options (jusqu'à 40) :
//! la version (4), la longueur de l'en-tête en mots de 32 bits (IHL), le
//! type de service, la longueur totale du paquet, l'identifiant et les
//! drapeaux de fragmentation, la durée de vie (TTL), le protocole de ce qui
//! suit (1 ICMP, 6 TCP, 17 UDP), la somme de contrôle de l'en-tête, et les
//! adresses de la source et de la destination. Les options d'un paquet
//! reçu se vérifient comme chez Linux (`compiler_options`), et leur écho
//! (`options_echo`) dit celles qu'on renverrait (IP_RETOPTS) ; celles
//! qu'un programme donne à ses envois (IP_OPTIONS, `options_a_envoyer`)
//! se complètent au départ de chaque paquet (`construire_options`).

use super::{Erreur, adresse, mot16, plier, somme};

/// La taille de l'en-tête sans options.
pub const ENTETE: usize = 20;
/// Les protocoles.
pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
/// IGMP (RFC 3376), les adhésions aux groupes de multidiffusion.
pub const IGMP: u8 = 2;
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

/// Écrit l'en-tête `h` dans `o`, l'en-tête entier : ses 20 premiers
/// octets, puis les options, déjà en place (`construire_options`) ; sa
/// longueur (IHL) est celle de `o` (`longueur_entete` est ignoré : un
/// multiple de 4, de 20 à 60), et sa somme couvre tout `o`.
pub fn ecrire(o: &mut [u8], h: &Ipv4) {
    o[0] = 0x40 | (o.len() / 4) as u8;
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

/// La découpe d'un paquet trop grand pour sa MTU (`ip_do_fragment` et
/// `ip_frag_next` de Linux) : `charge` octets après un en-tête de `entete`
/// octets (options comprises), pour la MTU `mtu`. Chaque fragment porte au
/// plus `mtu - entete` octets, et chacun de ceux qui ne finissent pas le
/// paquet un multiple de 8 (le décalage du suivant s'écrit en mots de 8
/// octets) : le dernier n'est jamais arrondi, et peut porter jusqu'à 7
/// octets de plus que les autres. La taille du fragment qui commence à
/// `debut`.
pub fn taille_du_fragment(charge: usize, debut: usize, mtu: usize, entete: usize) -> usize {
    let (reste, place) = (charge.saturating_sub(debut), place_d_un_fragment(mtu, entete));
    if reste <= place { reste } else { place & !7 }
}

/// Le nombre de fragments de cette découpe (`taille_du_fragment`) : un
/// seul si le paquet tient. C'est aussi la géométrie des `sk_buff` que
/// Linux enchaîne pour un datagramme (`__ip_append_data` coupe à
/// `maxfraglen`, sauf à la fin).
pub fn nombre_de_fragments(charge: usize, mtu: usize, entete: usize) -> usize {
    let place = place_d_un_fragment(mtu, entete);
    if charge <= place { 1 } else { 1 + (charge - place).div_ceil(place & !7) }
}

/// La place des données d'un fragment, au moins 8 octets : une MTU d'au
/// moins 68 octets (le minimum d'IPv4) les laisse toujours, même avec 40
/// octets d'options ; jamais de division par zéro.
fn place_d_un_fragment(mtu: usize, entete: usize) -> usize {
    mtu.saturating_sub(entete).max(8)
}

/// Une adresse de multidiffusion (224.0.0.0/4, la « classe D »).
pub fn multidiffusion(a: [u8; 4]) -> bool {
    a[0] & 0xF0 == 0xE0
}

/// Un groupe du lien (224.0.0.0/24, `ipv4_is_local_multicast`) : jamais
/// relayé par un routeur, quel que soit le TTL (224.0.0.1, tous les hôtes ;
/// 224.0.0.22, les rapports d'IGMPv3 ; 224.0.0.251, mDNS).
pub fn multidiffusion_du_lien(a: [u8; 4]) -> bool {
    a[0] == 224 && a[1] == 0 && a[2] == 0
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
/// comptée depuis son premier octet (0 : absente), et ce que la réception
/// y a écrit (`rr_needaddr`, `ts_needaddr`, `ts_needtime`), que relit leur
/// écho (`options_echo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    pub route_source: u8,
    /// La route source est stricte (SSRR).
    pub stricte: bool,
    pub route_notee: u8,
    /// La route notée avait de la place : notre adresse y est.
    pub route_notee_adresse: bool,
    pub horodatage: u8,
    /// L'horodatage avait de la place : notre adresse (drapeau 1) et
    /// l'heure (drapeaux 0 et 1, et 3 quand l'adresse donnée n'est pas
    /// quelqu'un d'autre) y sont.
    pub horodatage_adresse: bool,
    pub horodatage_heure: bool,
    pub alerte: u8,
    /// Des octets de l'en-tête ont changé (`is_changed`).
    pub modifiees: bool,
}

impl Options {
    /// Aucune option (le `Default`, utilisable dans une constante).
    pub const AUCUNES: Options = Options {
        route_source: 0, stricte: false, route_notee: 0, route_notee_adresse: false, horodatage: 0,
        horodatage_adresse: false, horodatage_heure: false, alerte: 0, modifiees: false,
    };
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

/// Une option fausse (`__ip_options_compile` rend -EINVAL) : l'octet
/// fautif, compté depuis le début de l'en-tête, que dira le « problème de
/// paramètre » (ICMP 12), et ce que la vérification avait déjà noté des
/// options qui la précèdent : Linux le laisse dans `IPCB(skb)->opt`, et
/// l'erreur ICMP en fait l'écho (`__icmp_send`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Faute {
    pub place: u8,
    pub options: Options,
}

/// Pour qui vérifie-t-on des options (le `skb` de `__ip_options_compile`,
/// présent ou non) : un paquet reçu, où l'on note ce qu'il faut (`Ici`) ;
/// ou un programme qui en donne à envoyer, avec ou sans CAP_NET_RAW
/// (`racine`), et ce qui dit si une adresse est quelqu'un d'autre.
enum Pour<'a> {
    Reception(&'a Ici<'a>),
    Envoi { racine: bool, unicast: &'a dyn Fn([u8; 4]) -> bool },
}

/// Les options de l'en-tête reçu `entete` (en entier, ses 20 premiers
/// octets compris), vérifiées une à une et complétées sur place comme
/// `__ip_options_compile` de Linux (net/ipv4/ip_options.c) pour un paquet
/// reçu. Une option fausse : `Err`, avec l'octet fautif et ce qui précède
/// (`Faute`) ; le paquet est jeté.
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
pub fn compiler_options(entete: &mut [u8], ici: &Ici) -> Result<Options, Faute> {
    compiler(entete, &Pour::Reception(ici), &mut [0; 4])
}

/// Des options données par un programme pour ses envois (IP_OPTIONS, et le
/// message de contrôle IP_RETOPTS : `ip_options_get`) : 40 octets au plus,
/// complétées de FIN jusqu'à un mot entier, puis vérifiées comme pour un
/// paquet reçu (`compiler_options`), avec ce qui change sans paquet
/// (`__ip_options_compile` sans skb) : rien n'est écrit, seules les places
/// sont réservées (le pointeur avance, et l'envoi les remplira :
/// `construire_options`) ; le débordement de l'horodatage ne compte pas ;
/// une route source doit avoir son pointeur à 4, au moins une étape et
/// des mots entiers (longueur 7, 11...), et sa première étape en sort
/// (`premier_saut` : le paquet ira là d'abord ; les autres avancent d'un
/// mot, et le dernier recevra la vraie destination) ; sans CAP_NET_RAW
/// (`racine`), un drapeau d'horodatage inconnu, la sécurité, l'identifiant
/// de flux, CIPSO et une option inconnue sont refusés (CIPSO l'est
/// toujours : aucun domaine). Une faute, ou plus de 40 octets : `Err`
/// (EINVAL). Aucun octet : aucune option.
pub fn options_a_envoyer(donnees: &[u8], racine: bool, unicast: &dyn Fn([u8; 4]) -> bool)
                         -> Result<OptionsSortantes, ()> {
    if donnees.len() > OPTIONS_MAX {
        return Err(());
    }
    let longueur = donnees.len().next_multiple_of(4);
    let mut entete = [option::FIN; ENTETE + OPTIONS_MAX];
    entete[ENTETE..ENTETE + donnees.len()].copy_from_slice(donnees);
    let mut premier_saut = [0; 4];
    let places = compiler(&mut entete[..ENTETE + longueur], &Pour::Envoi { racine, unicast }, &mut premier_saut)
        .map_err(|_| ())?;
    let mut octets = [0; OPTIONS_MAX];
    octets.copy_from_slice(&entete[ENTETE..]);
    Ok(OptionsSortantes { octets, longueur: longueur as u8, places, premier_saut })
}

/// `__ip_options_compile` : voir `compiler_options` et `options_a_envoyer`.
fn compiler(entete: &mut [u8], pour: &Pour, premier_saut: &mut [u8; 4]) -> Result<Options, Faute> {
    use option::*;
    let (ici, interdite, unicast) = match pour {
        Pour::Reception(ici) => (Some(*ici), false, ici.unicast),
        Pour::Envoi { racine, unicast } => (None, !racine, *unicast),
    };
    let mut opt = Options::default();
    let faute = |place: usize, options: Options| -> Result<Options, Faute> { Err(Faute { place: place as u8, options }) };
    let mut k = ENTETE;
    let fin = entete.len();
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
            return faute(k, opt);
        }
        let longueur = entete[k + 1] as usize;
        if longueur < 2 || longueur > reste {
            return faute(k, opt);
        }
        let o = &mut entete[k..k + longueur];
        match o[0] {
            ROUTE_SOURCE_LACHE | ROUTE_SOURCE_STRICTE => {
                if longueur < 3 {
                    return faute(k + 1, opt);
                }
                if o[2] < 4 {
                    return faute(k + 2, opt);
                }
                if opt.route_source != 0 {
                    return faute(k, opt);
                }
                if ici.is_none() {
                    if o[2] != 4 || longueur < 7 || (longueur - 3) % 4 != 0 {
                        return faute(k + 1, opt);
                    }
                    premier_saut.copy_from_slice(&o[3..7]);
                    o.copy_within(7.., 3);
                }
                opt.stricte = o[0] == ROUTE_SOURCE_STRICTE;
                opt.route_source = k as u8;
            }
            ROUTE_NOTEE => {
                if opt.route_notee != 0 {
                    return faute(k, opt);
                }
                if longueur < 3 {
                    return faute(k + 1, opt);
                }
                let pointeur = o[2] as usize;
                if pointeur < 4 {
                    return faute(k + 2, opt);
                }
                if pointeur <= longueur {
                    if pointeur + 3 > longueur {
                        return faute(k + 2, opt);
                    }
                    if let Some(ici) = ici {
                        o[pointeur - 1..pointeur + 3].copy_from_slice(&ici.adresse);
                        opt.modifiees = true;
                    }
                    o[2] += 4;
                    opt.route_notee_adresse = true;
                }
                opt.route_notee = k as u8;
            }
            HORODATAGE => {
                if opt.horodatage != 0 {
                    return faute(k, opt);
                }
                if longueur < 4 {
                    return faute(k + 1, opt);
                }
                let pointeur = o[2] as usize;
                if pointeur < 5 {
                    return faute(k + 2, opt);
                }
                let drapeau = o[3] & 0xF;
                if pointeur <= longueur {
                    if pointeur + 3 > longueur {
                        return faute(k + 2, opt);
                    }
                    // Où écrire l'heure (à la réception seulement).
                    let heure = match drapeau {
                        HEURE_SEULE => {
                            o[2] += 4;
                            opt.horodatage_heure = true;
                            Some(pointeur - 1)
                        }
                        HEURE_ET_ADRESSE | ADRESSES_DONNEES => {
                            if pointeur + 7 > longueur {
                                return faute(k + 2, opt);
                            }
                            let a = [o[pointeur - 1], o[pointeur], o[pointeur + 1], o[pointeur + 2]];
                            if drapeau == ADRESSES_DONNEES && unicast(a) {
                                None
                            } else {
                                if drapeau == HEURE_ET_ADRESSE {
                                    if let Some(ici) = ici {
                                        o[pointeur - 1..pointeur + 3].copy_from_slice(&ici.adresse);
                                    }
                                    opt.horodatage_adresse = true;
                                }
                                opt.horodatage_heure = true;
                                o[2] += 8;
                                Some(pointeur + 3)
                            }
                        }
                        _ if interdite => return faute(k + 3, opt),
                        _ => None,
                    };
                    if let (Some(h), Some(ici)) = (heure, ici) {
                        o[h..h + 4].copy_from_slice(&ici.heure.to_be_bytes());
                        opt.modifiees = true;
                    }
                } else if drapeau != ADRESSES_DONNEES {
                    let debordement = o[3] >> 4;
                    if debordement == 15 {
                        return faute(k + 3, opt);
                    }
                    if ici.is_some() {
                        o[3] = drapeau | ((debordement + 1) << 4);
                        opt.modifiees = true;
                    }
                }
                opt.horodatage = k as u8;
            }
            ALERTE => {
                if longueur < 4 {
                    return faute(k + 1, opt);
                }
                if o[2] == 0 && o[3] == 0 {
                    opt.alerte = k as u8;
                }
            }
            CIPSO if interdite => return faute(k, opt),
            CIPSO => return faute(if longueur < 8 { k + 1 } else { k + 2 }, opt),
            _ if interdite => return faute(k, opt),
            _ => {}
        }
        k += longueur;
    }
    Ok(opt)
}

/// La place des options dans un en-tête : 40 octets au plus (15 mots
/// moins les 5 de l'en-tête fixe).
pub const OPTIONS_MAX: usize = 40;

/// Des options à envoyer (le `struct ip_options` de Linux, avec ses
/// octets `__data`) : leurs octets (complétés de FIN jusqu'à un multiple
/// de 4), la place de chacune comme dans `Options` (comptée depuis le début
/// de l'en-tête), ce que l'envoi y écrira, et pour une route source, la
/// première étape (`faddr`), où le paquet ira d'abord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionsSortantes {
    pub octets: [u8; OPTIONS_MAX],
    pub longueur: u8,
    pub places: Options,
    pub premier_saut: [u8; 4],
}

impl OptionsSortantes {
    /// Aucune option.
    pub const AUCUNE: OptionsSortantes =
        OptionsSortantes { octets: [0; OPTIONS_MAX], longueur: 0, places: Options::AUCUNES, premier_saut: [0; 4] };

    /// Les octets des options.
    pub fn octets(&self) -> &[u8] {
        &self.octets[..self.longueur as usize]
    }

    /// Les remet comme avant ce que l'envoi y écrirait (`ip_options_undo`) :
    /// la première étape d'une route source revient devant les autres, et
    /// chaque place réservée à notre adresse ou à l'heure est rendue (le
    /// pointeur recule, l'emplacement revient à 0). C'est ce que voit le
    /// programme (IP_RETOPTS, et `getsockopt` d'IP_OPTIONS) : des options
    /// qu'il peut redonner telles quelles à l'envoi.
    pub fn defaire(&mut self) {
        let base = |place: u8| place as usize - ENTETE;
        let p = self.places;
        if p.route_source != 0 {
            let k = base(p.route_source);
            let l = self.octets[k + 1] as usize;
            self.octets.copy_within(k + 3..k + l - 4, k + 7);
            self.octets[k + 3..k + 7].copy_from_slice(&self.premier_saut);
        }
        // Rendre l'emplacement d'avant le pointeur de l'option en `k`.
        let rendre = |o: &mut [u8; OPTIONS_MAX], k: usize| {
            o[k + 2] -= 4;
            let v = o[k + 2] as usize;
            o[k + v - 1..k + v + 3].fill(0);
        };
        if p.route_notee_adresse {
            rendre(&mut self.octets, base(p.route_notee));
        }
        if p.horodatage != 0 {
            let k = base(p.horodatage);
            if p.horodatage_heure {
                rendre(&mut self.octets, k);
                if self.octets[k + 3] & 0xF == option::ADRESSES_DONNEES {
                    self.octets[k + 2] -= 4;
                }
            }
            if p.horodatage_adresse {
                rendre(&mut self.octets, k);
            }
        }
    }
}

/// L'écho des options d'un paquet reçu (`__ip_options_echo`) : celles d'une
/// réponse qui doit refaire le même chemin à l'envers, ou que montre
/// IP_RETOPTS. `options` : les options reçues (après `compiler_options`,
/// qui a dit `o`), `source` : la source du paquet. Dans l'ordre de Linux :
///
/// - la route notée, recopiée ; s'il y reste la place de notre adresse
///   (que la réception a déjà notée), l'envoi y écrira la sienne ;
/// - l'horodatage, recopié ; s'il y reste de la place, l'envoi y écrira
///   l'heure (et l'adresse) ; pour les adresses données d'avance, l'heure
///   seulement si la suivante n'est pas quelqu'un d'autre ;
/// - la route source, retournée : les étapes déjà faites, de la dernière à
///   la première, la plus récente devenant la première étape du retour ;
///   la source du paquet, si elle y est encore, retirée (la RFC 1812,
///   5.2.4.1, veut qu'on répare une route qui la contient) ;
/// - (Linux recopie aussi une étiquette CIPSO, que nous n'acceptons jamais.)
///
/// Une place annoncée qui ne tient pas dans l'option : `Err`, et Linux ne
/// répond pas (une erreur ICMP, l'écho, se taisent ; IP_RETOPTS donne
/// MSG_CTRUNC).
pub fn options_echo(options: &[u8], o: &Options, source: [u8; 4], unicast: &dyn Fn([u8; 4]) -> bool)
                    -> Result<OptionsSortantes, ()> {
    let mut d = OptionsSortantes::AUCUNE;
    if options.is_empty() {
        return Ok(d);
    }
    let base = |place: u8| place as usize - ENTETE;
    // L'option qui commence à `k` (la vérification a vu qu'elle tient).
    let option = |k: usize| options.get(k..k + *options.get(k + 1)? as usize);
    let mut n = 0usize;
    if o.route_notee != 0 {
        let s = option(base(o.route_notee)).ok_or(())?;
        let (longueur, pointeur) = (s[1] as usize, s[2] as usize);
        d.places.route_notee = (n + ENTETE) as u8;
        d.octets[n..n + longueur].copy_from_slice(s);
        if o.route_notee_adresse && pointeur <= longueur {
            if pointeur + 3 > longueur {
                return Err(());
            }
            d.octets[n + 2] = (pointeur + 4) as u8;
            d.places.route_notee_adresse = true;
        }
        n += longueur;
    }
    if o.horodatage != 0 {
        let s = option(base(o.horodatage)).ok_or(())?;
        let (longueur, mut pointeur) = (s[1] as usize, s[2] as usize);
        d.places.horodatage = (n + ENTETE) as u8;
        d.octets[n..n + longueur].copy_from_slice(s);
        if pointeur <= longueur {
            if o.horodatage_adresse {
                if pointeur + 3 > longueur {
                    return Err(());
                }
                d.places.horodatage_adresse = true;
                pointeur += 4;
            }
            if o.horodatage_heure {
                if pointeur + 3 > longueur {
                    return Err(());
                }
                if s[3] & 0xF != option::ADRESSES_DONNEES {
                    d.places.horodatage_heure = true;
                    pointeur += 4;
                } else if pointeur + 7 <= longueur {
                    let a = [s[pointeur - 1], s[pointeur], s[pointeur + 1], s[pointeur + 2]];
                    if !unicast(a) {
                        d.places.horodatage_heure = true;
                        pointeur += 8;
                    }
                }
            }
            d.octets[n + 2] = pointeur as u8;
        }
        n += longueur;
    }
    if o.route_source != 0 {
        let s = option(base(o.route_source)).ok_or(())?;
        let longueur = s[1] as usize;
        // Les étapes déjà faites : celles avant le pointeur (s'il dépasse la
        // fin, toutes). `lu` montre (comme le pointeur, depuis 1) l'étape à
        // recopier ; `ecrit`, la place où elle va.
        let mut lu = (s[2] as usize).min(longueur + 1) - 4;
        let mut ecrit = 0;
        let mut premier_saut = [0; 4];
        if lu > 3 {
            premier_saut.copy_from_slice(&s[lu - 1..lu + 3]);
            lu -= 4;
            ecrit = 4;
            while lu > 3 {
                d.octets[n + ecrit - 1..n + ecrit + 3].copy_from_slice(&s[lu - 1..lu + 3]);
                lu -= 4;
                ecrit += 4;
            }
            if s[lu + 3..lu + 7] == source {
                ecrit -= 4;
            }
        }
        if ecrit > 3 {
            d.premier_saut = premier_saut;
            d.octets[n] = s[0];
            d.octets[n + 1] = (ecrit + 3) as u8;
            d.octets[n + 2] = 4;
            d.places.route_source = (n + ENTETE) as u8;
            d.places.stricte = o.stricte;
            n += ecrit + 3;
        }
    }
    // Complétées de FIN jusqu'à un mot entier (déjà nulles).
    d.longueur = n.next_multiple_of(4) as u8;
    Ok(d)
}

/// Écrit un mot de 4 octets à la place `k` de `o`, s'il y tient (des
/// places faites par `options_a_envoyer` ou `options_echo` y tiennent
/// toujours).
fn ecrire_mot(o: &mut [u8], k: usize, v: [u8; 4]) {
    if let Some(m) = o.get_mut(k..k + 4) {
        m.copy_from_slice(&v);
    }
}

/// Les options `o` d'un paquet qui part, mises dans son en-tête `entete`
/// (après ses 20 premiers octets ; `entete` en a la place) et complétées
/// comme `ip_options_build` : la vraie destination `destination` dans le
/// dernier mot d'une route source (l'en-tête, lui, va à sa première étape) ;
/// dans les places réservées, notre adresse `source` (celle de l'en-tête :
/// `ip_rt_get_source` d'une route de sortie) pour la route notée et
/// l'horodatage avec adresses, et l'heure `heure` (les millisecondes depuis
/// minuit, temps universel). Le paquet n'est fait qu'une fois : ses
/// fragments partagent ces options (`options_de_fragment`).
pub fn construire_options(entete: &mut [u8], o: &OptionsSortantes, destination: [u8; 4], source: [u8; 4], heure: u32) {
    let n = o.longueur as usize;
    let Some(place) = entete.get_mut(ENTETE..ENTETE + n) else { return };
    place.copy_from_slice(o.octets());
    let p = o.places;
    // Le pointeur de l'option en `k`, moins `recul`.
    let avant = |e: &[u8], k: usize, recul: usize| (k + *e.get(k + 2).unwrap_or(&0) as usize).checked_sub(recul);
    if p.route_source != 0 {
        let k = p.route_source as usize;
        if let Some(m) = (k + *entete.get(k + 1).unwrap_or(&0) as usize).checked_sub(4) {
            ecrire_mot(entete, m, destination);
        }
    }
    if p.route_notee_adresse
        && let Some(m) = avant(entete, p.route_notee as usize, 5)
    {
        ecrire_mot(entete, m, source);
    }
    if p.horodatage_adresse
        && let Some(m) = avant(entete, p.horodatage as usize, 9)
    {
        ecrire_mot(entete, m, source);
    }
    if p.horodatage_heure
        && let Some(m) = avant(entete, p.horodatage as usize, 5)
    {
        ecrire_mot(entete, m, heure.to_be_bytes());
    }
}

/// Les options d'un fragment après le premier (`ip_options_fragment`) :
/// celles qui ne se recopient pas dans chaque fragment (le bit « copiée »,
/// 0x80, de leur genre est nul : la route notée, l'horodatage) deviennent
/// des bourrages ; les autres (les routes sources, la sécurité, l'alerte aux
/// routeurs) restent. Une option mal formée arrête tout (elles viennent de
/// nous : jamais).
pub fn options_de_fragment(options: &mut [u8]) {
    let mut k = 0;
    while k < options.len() {
        match options[k] {
            option::FIN => return,
            option::BOURRAGE => {
                k += 1;
                continue;
            }
            _ => {}
        }
        let l = options.get(k + 1).map_or(0, |&l| l as usize);
        if l < 2 || l > options.len() - k {
            return;
        }
        if options[k] & 0x80 == 0 {
            options[k..k + l].fill(option::BOURRAGE);
        }
        k += l;
    }
}
