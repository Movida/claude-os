//! L'en-tête de TCP (RFC 9293, 3.1) : les ports, le numéro de séquence et
//! celui qu'on acquitte, la longueur de l'en-tête (en mots de 32 bits),
//! les drapeaux, la fenêtre, la somme (avec le pseudo-en-tête d'IPv4, comme
//! UDP), le pointeur urgent, puis des options.
//!
//! Les options que nous lisons et écrivons : MSS (la plus grande charge que
//! l'autre veut recevoir, dans un SYN), l'échelle de fenêtre (RFC 7323, dans
//! un SYN : la fenêtre annoncée sera décalée d'autant de bits), et les
//! horodatages (RFC 7323, dans tout segment : notre heure, et la dernière
//! heure reçue de l'autre). Les autres sont sautées, par leur longueur. La
//! lecture suit `tcp_parse_options` de Linux : EOL arrête, NOP fait un octet,
//! une longueur de moins de 2 ou qui déborde arrête la lecture des options
//! SANS refuser le segment (Linux non plus) ; MSS et l'échelle ne valent que
//! dans un SYN, et toutes avec leur longueur exacte. L'écriture suit
//! `tcp_options_write` : chaque option alignée sur 32 bits par des NOP.

use super::{Erreur, mot16, mot32, plier, somme};

/// La taille de l'en-tête sans options.
pub const ENTETE: usize = 20;
/// La plus grande échelle de fenêtre (RFC 7323 : 14).
pub const ECHELLE_MAX: u8 = 14;

// Les drapeaux.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

// Les options.
const EOL: u8 = 0;
const NOP: u8 = 1;
const MSS: u8 = 2;
const ECHELLE: u8 = 3;
const HORODATAGE: u8 = 8;

/// Les options qui nous intéressent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    pub mss: Option<u16>,
    pub echelle: Option<u8>,
    /// Les horodatages : (TSval, TSecr).
    pub horodatage: Option<(u32, u32)>,
}

/// Un en-tête TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tcp {
    pub source: u16,
    pub destination: u16,
    pub seq: u32,
    pub ack: u32,
    pub drapeaux: u8,
    pub fenetre: u16,
    pub urgent: u16,
    pub options: Options,
}

/// La somme du pseudo-en-tête d'IPv4.
fn pseudo(source: [u8; 4], destination: [u8; 4], longueur: u16) -> u32 {
    let mut p = [0u8; 12];
    p[..4].copy_from_slice(&source);
    p[4..8].copy_from_slice(&destination);
    p[9] = super::ipv4::TCP;
    p[10..].copy_from_slice(&longueur.to_be_bytes());
    somme(&p, 0)
}

/// Lit les options de `o` (ce qui suit les 20 octets de l'en-tête).
fn options(mut o: &[u8], syn: bool) -> Options {
    let mut r = Options::default();
    while let Some(&genre) = o.first() {
        match genre {
            EOL => break,
            NOP => o = &o[1..],
            _ => {
                let Some(&longueur) = o.get(1) else { break };
                let longueur = longueur as usize;
                if longueur < 2 || longueur > o.len() {
                    break;
                }
                match (genre, longueur) {
                    (MSS, 4) if syn => r.mss = mot16(o, 2),
                    // Une échelle au-delà de 14 compte pour 14 (Linux le
                    // dit, et la borne).
                    (ECHELLE, 3) if syn => r.echelle = Some(o[2].min(ECHELLE_MAX)),
                    (HORODATAGE, 10) => r.horodatage = mot32(o, 2).zip(mot32(o, 6)),
                    _ => {}
                }
                o = &o[longueur..];
            }
        }
    }
    r
}

/// Lit le segment `o` (la charge d'un paquet IPv4 de `source` vers
/// `destination`) : son en-tête et sa charge. La longueur de l'en-tête au
/// moins 20 octets et dans le segment ; la somme vérifiée si `verifier`
/// (pas pour un paquet de `lo`, comme Linux : `loopback.c` dit sa somme
/// déjà bonne).
pub fn lire(o: &[u8], source: [u8; 4], destination: [u8; 4], verifier: bool) -> Result<(Tcp, &[u8]), Erreur> {
    let e = o.get(..ENTETE).ok_or(Erreur::Tronque)?;
    let longueur_entete = (e[12] >> 4) as usize * 4;
    if longueur_entete < ENTETE {
        return Err(Erreur::Invalide);
    }
    if longueur_entete > o.len() {
        return Err(Erreur::Tronque);
    }
    if verifier && (o.len() > u16::MAX as usize || plier(somme(o, pseudo(source, destination, o.len() as u16))) != 0) {
        return Err(Erreur::Somme);
    }
    let drapeaux = e[13];
    let t = Tcp {
        source: mot16(e, 0).ok_or(Erreur::Tronque)?,
        destination: mot16(e, 2).ok_or(Erreur::Tronque)?,
        seq: mot32(e, 4).ok_or(Erreur::Tronque)?,
        ack: mot32(e, 8).ok_or(Erreur::Tronque)?,
        drapeaux,
        fenetre: mot16(e, 14).ok_or(Erreur::Tronque)?,
        urgent: mot16(e, 18).ok_or(Erreur::Tronque)?,
        options: options(&o[ENTETE..longueur_entete], drapeaux & SYN != 0),
    };
    Ok((t, &o[longueur_entete..]))
}

/// La longueur de l'en-tête qu'écrira `ecrire` pour ces options : 20, plus
/// 4 pour MSS, plus 12 pour les horodatages (deux NOP, puis l'option de 10
/// octets), plus 4 pour l'échelle (NOP puis l'option de 3 octets).
pub fn longueur_entete(o: &Options) -> usize {
    ENTETE + if o.mss.is_some() { 4 } else { 0 } + if o.horodatage.is_some() { 12 } else { 0 } + if o.echelle.is_some() { 4 } else { 0 }
}

/// Écrit l'en-tête de `t` au début de `o` (la place de l'en-tête, puis la
/// charge déjà en place ; `o` fait au plus 65 535 octets), avec sa somme
/// si `somme_voulue` (pas par `lo` : 0, comme Linux qui ne la calcule pas).
pub fn ecrire(o: &mut [u8], t: &Tcp, source: [u8; 4], destination: [u8; 4], somme_voulue: bool) {
    let n = longueur_entete(&t.options);
    o[0..2].copy_from_slice(&t.source.to_be_bytes());
    o[2..4].copy_from_slice(&t.destination.to_be_bytes());
    o[4..8].copy_from_slice(&t.seq.to_be_bytes());
    o[8..12].copy_from_slice(&t.ack.to_be_bytes());
    o[12] = ((n / 4) as u8) << 4;
    o[13] = t.drapeaux;
    o[14..16].copy_from_slice(&t.fenetre.to_be_bytes());
    o[16..18].fill(0);
    o[18..20].copy_from_slice(&t.urgent.to_be_bytes());
    let mut i = ENTETE;
    if let Some(mss) = t.options.mss {
        o[i] = MSS;
        o[i + 1] = 4;
        o[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
        i += 4;
    }
    if let Some((val, ecr)) = t.options.horodatage {
        o[i..i + 4].copy_from_slice(&[NOP, NOP, HORODATAGE, 10]);
        o[i + 4..i + 8].copy_from_slice(&val.to_be_bytes());
        o[i + 8..i + 12].copy_from_slice(&ecr.to_be_bytes());
        i += 12;
    }
    if let Some(e) = t.options.echelle {
        o[i..i + 4].copy_from_slice(&[NOP, ECHELLE, 3, e]);
    }
    if somme_voulue {
        let s = plier(somme(o, pseudo(source, destination, o.len() as u16)));
        o[16..18].copy_from_slice(&s.to_be_bytes());
    }
}
