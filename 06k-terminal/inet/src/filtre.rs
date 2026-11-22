//! Les filtres des sockets (SO_ATTACH_FILTER) : le BPF classique, « cBPF ».
//!
//! Un programme qui s'attache à une socket et voit chaque paquet qu'elle
//! reçoit : il rend le nombre d'octets à garder (0 : le paquet est jeté).
//! C'est le filtre de tcpdump (`tcpdump -dd` écrit ces instructions), et le
//! plus ancien des BPF : deux registres de 32 bits (A et X), seize mots de
//! mémoire (M[0] à M[15]), des sauts seulement en avant (un programme finit
//! toujours, sans boucle), et des lectures du paquet bornées.
//!
//! Ici, sans matériel ni verrou :
//!   - `verifier` : ce que Linux refuse (EINVAL) avant d'accepter un
//!     programme (`bpf_check_classic`, `check_load_and_stores`) ;
//!   - `longueur_convertie` et `taille` : ce que le programme compte dans la
//!     mémoire des options de sa socket (SO_MEMINFO, `sk_omem_alloc`). Linux
//!     ne garde pas le programme tel quel : il le traduit en eBPF
//!     (`bpf_convert_filter`), et compte la taille de la traduction
//!     (`bpf_prog_size`). Nous ne traduisons rien (voir plus bas), mais
//!     calculons la longueur qu'aurait la traduction, instruction par
//!     instruction : la mémoire comptée, et le seul refus qui vient de la
//!     traduction (un saut trop long pour ses 16 bits), sont ceux de Linux ;
//!   - `executer` : le programme sur un paquet (`Vue`).
//!
//! Choix de conception : un interpréteur du BPF classique, pas une
//! traduction en eBPF. Linux traduit pour n'avoir qu'une machine (l'eBPF,
//! son interpréteur et ses compilateurs à la volée) ; nous n'avons pas
//! d'eBPF (pas d'appel `bpf`), et la traduction n'existerait que pour être
//! interprétée ensuite. L'interpréteur du BPF classique est l'original (le
//! `sk_run_filter` de Linux jusqu'en 3.15, celui des BSD encore) : une boucle
//! sur les instructions, qui ne peut pas déborder (les sauts sont vérifiés
//! en avant, la mémoire M[] écrite avant d'être lue). Ce qu'il rend est
//! celui de la traduction de Linux, dans chaque cas où les deux pourraient
//! diverger : les décalages au-delà de 31 bits (masqués, comme le `shl` de
//! x86 qu'émet son compilateur), la division par zéro (le programme rend
//! 0), une lecture hors du paquet (0 aussi), une extension sans carte (le
//! programme rend A tel quel : voir `Extension::Interface`).
//!
//! Rien ici ne tire au hasard : SKF_AD_RANDOM demande un nombre à `hasard`.

use alloc::vec::Vec;
use faillible::{avec_capacite, remplie, VecFaillible};

/// La longueur maximale d'un programme (`BPF_MAXINSNS`).
pub const MAX_INSTRUCTIONS: usize = 4096;
/// Les mots de la mémoire M[] (`BPF_MEMWORDS`).
pub const MOTS: usize = 16;
/// SO_BPF_EXTENSIONS : la première extension inconnue (`SKF_AD_MAX`).
pub const EXTENSIONS: u32 = 64;

/// Les lectures d'au-delà du paquet : une extension (la valeur d'un champ
/// du paquet, pas un octet), un octet compté depuis l'en-tête de réseau
/// (IPv4), ou depuis celui de liaison (Ethernet).
pub const SKF_AD_OFF: i32 = -0x1000;
pub const SKF_NET_OFF: i32 = -0x10_0000;
pub const SKF_LL_OFF: i32 = -0x20_0000;

/// Une instruction (`struct sock_filter`, 8 octets) : le code, les deux
/// sauts (si vrai, si faux) d'une comparaison, et la constante.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl Instruction {
    pub const TAILLE: usize = 8;

    /// Celle que donne le programme (ordre de la machine : x86_64).
    pub fn lire(o: [u8; 8]) -> Instruction {
        Instruction { code: u16::from_le_bytes([o[0], o[1]]), jt: o[2], jf: o[3], k: u32::from_le_bytes([o[4], o[5], o[6], o[7]]) }
    }

    pub fn octets(&self) -> [u8; 8] {
        let (c, k) = (self.code.to_le_bytes(), self.k.to_le_bytes());
        [c[0], c[1], self.jt, self.jf, k[0], k[1], k[2], k[3]]
    }
}

// Le code : la classe (3 bits), puis la taille et le mode d'une lecture, ou
// l'opération et la source (K : la constante, X : le registre) d'un calcul
// ou d'un saut.
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;
const W: u16 = 0x00;
const H: u16 = 0x08;
const B: u16 = 0x10;
const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const MEM: u16 = 0x60;
const LEN: u16 = 0x80;
const MSH: u16 = 0xa0;
const ADD: u16 = 0x00;
const SUB: u16 = 0x10;
const MUL: u16 = 0x20;
const DIV: u16 = 0x30;
const OR: u16 = 0x40;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const RSH: u16 = 0x70;
const NEG: u16 = 0x80;
const MOD: u16 = 0x90;
const XOR: u16 = 0xa0;
const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JGT: u16 = 0x20;
const JGE: u16 = 0x30;
const JSET: u16 = 0x40;
const K: u16 = 0x00;
const X: u16 = 0x08;
/// RET A (`BPF_A`), et MISC TAX, TXA.
const A: u16 = 0x10;
const TAX: u16 = 0x00;
const TXA: u16 = 0x80;

/// Les codes permis (`chk_code_allowed`) : une table, pas des règles par
/// champ, comme Linux (un bit de trop, `ret x`, `ld h #k`, est refusé).
fn permis(code: u16) -> bool {
    matches!(
        code,
        // Les calculs, sur K ou X ; NEG seul.
        0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c | 0x94 | 0x9c | 0x54 | 0x5c | 0x44 | 0x4c | 0xa4 | 0xac
            | 0x64 | 0x6c | 0x74 | 0x7c | 0x84
            // LD : ABS (W, H, B), LEN, IND (W, H, B), IMM, MEM.
            | 0x20 | 0x28 | 0x30 | 0x80 | 0x40 | 0x48 | 0x50 | 0x00 | 0x60
            // LDX : LEN, B MSH, IMM, MEM ; ST, STX ; TAX, TXA ; RET K, RET A.
            | 0x81 | 0xb1 | 0x01 | 0x61 | 0x02 | 0x03 | 0x07 | 0x87 | 0x06 | 0x16
            // Les sauts : JA ; JEQ, JGE, JGT, JSET sur K ou X.
            | 0x05 | 0x15 | 0x1d | 0x35 | 0x3d | 0x25 | 0x2d | 0x45 | 0x4d
    )
}

/// Les extensions (`SKF_AD_*`, à `SKF_AD_OFF` + leur numéro) : ce qu'une
/// lecture ABS y trouve n'est pas un octet du paquet, mais un champ de son
/// `sk_buff`, ou un service (le processeur, un nombre au hasard). Quelle que
/// soit la taille de la lecture (`ldb [ad+0]` rend les 16 bits du protocole :
/// mesuré, la traduction ne regarde que la constante).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Extension {
    Protocole,
    Genre,
    /// SKF_AD_IFINDEX et SKF_AD_HATYPE : l'index et le type (ARPHRD_*) de la
    /// carte d'arrivée. Sans carte (AF_UNIX), la traduction de Linux sort du
    /// programme (`BPF_EXIT_INSN`) en rendant A tel qu'il est : mesuré.
    Interface { genre: bool },
    Attribut { imbrique: bool },
    Marque,
    File,
    Hachage,
    Processeur,
    XorX,
    VlanEtiquette,
    VlanPresent,
    DecalageCharge,
    Hasard,
    VlanProtocole,
}

fn extension(k: u32) -> Option<Extension> {
    let n = (k as i32).checked_sub(SKF_AD_OFF)?;
    Some(match n {
        0 => Extension::Protocole,
        4 => Extension::Genre,
        8 => Extension::Interface { genre: false },
        12 => Extension::Attribut { imbrique: false },
        16 => Extension::Attribut { imbrique: true },
        20 => Extension::Marque,
        24 => Extension::File,
        28 => Extension::Interface { genre: true },
        32 => Extension::Hachage,
        36 => Extension::Processeur,
        40 => Extension::XorX,
        44 => Extension::VlanEtiquette,
        48 => Extension::VlanPresent,
        52 => Extension::DecalageCharge,
        56 => Extension::Hasard,
        60 => Extension::VlanProtocole,
        _ => return None,
    })
}

/// Pourquoi un programme est refusé : EINVAL, ou ENOMEM (les tables de la
/// vérification et de la traduction, que Linux alloue aussi).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refus {
    Invalide,
    Memoire,
}

/// La vérification de Linux (`bpf_check_basics_ok`, `bpf_check_classic`,
/// `check_load_and_stores`), dans son ordre : la longueur ; chaque
/// instruction (code permis, division ou modulo par la constante 0, décalage
/// de 32 bits ou plus, mot de mémoire au-delà de M[15], saut hors du
/// programme, extension inconnue) ; un RET à la fin ; puis aucun mot de
/// mémoire lu sur un chemin où il n'a pas été écrit.
pub fn verifier(p: &[Instruction]) -> Result<(), Refus> {
    let n = p.len();
    if n == 0 || n > MAX_INSTRUCTIONS {
        return Err(Refus::Invalide);
    }
    for (pc, i) in p.iter().enumerate() {
        if !permis(i.code) {
            return Err(Refus::Invalide);
        }
        let juste = match i.code {
            c if c == ALU | DIV | K || c == ALU | MOD | K => i.k != 0,
            c if c == ALU | LSH | K || c == ALU | RSH | K => i.k < 32,
            c if c == LD | MEM || c == LDX | MEM || c == ST || c == STX => (i.k as usize) < MOTS,
            // Sur 32 bits, comme Linux : `k >= flen - pc - 1`.
            c if c == JMP | JA => i.k < (n - pc - 1) as u32,
            c if c & 0x07 == JMP => pc + i.jt as usize + 1 < n && pc + i.jf as usize + 1 < n,
            // Au-delà de SKF_AD_OFF (comparés sans signe), seules les
            // extensions connues ; en deçà (SKF_NET_OFF, SKF_LL_OFF, et tout
            // autre décalage négatif), la lecture décidera.
            c if c == LD | W | ABS || c == LD | H | ABS || c == LD | B | ABS => {
                extension(i.k).is_some() || i.k < SKF_AD_OFF as u32
            }
            _ => true,
        };
        if !juste {
            return Err(Refus::Invalide);
        }
    }
    if !matches!(p[n - 1].code, c if c == RET | K || c == RET | A) {
        return Err(Refus::Invalide);
    }
    memoire_ecrite(p)
}

/// `check_load_and_stores` : pour chaque instruction, les mots de M[] écrits
/// sur tous les chemins qui y mènent (un masque de 16 bits) ; une lecture
/// d'un mot qui ne l'est pas sur l'un d'eux : refusée. Comme Linux, une
/// instruction qui suit un RET hérite encore de ce qui précédait (la passe
/// ne sait pas qu'on n'y arrive pas en tombant).
fn memoire_ecrite(p: &[Instruction]) -> Result<(), Refus> {
    let mut masques: Vec<u16> = remplie(p.len(), 0xffff).map_err(|_| Refus::Memoire)?;
    let mut ecrits: u16 = 0;
    for (pc, i) in p.iter().enumerate() {
        ecrits &= masques[pc];
        match i.code {
            c if c == ST || c == STX => ecrits |= 1 << i.k,
            c if c == LD | MEM || c == LDX | MEM => {
                if ecrits & (1 << i.k) == 0 {
                    return Err(Refus::Invalide);
                }
            }
            c if c == JMP | JA => {
                masques[pc + 1 + i.k as usize] &= ecrits;
                ecrits = 0xffff;
            }
            c if c & 0x07 == JMP => {
                masques[pc + 1 + i.jt as usize] &= ecrits;
                masques[pc + 1 + i.jf as usize] &= ecrits;
                ecrits = 0xffff;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Le saut le plus long que code une instruction d'eBPF (16 bits signés).
const SAUT_MAX: i64 = i16::MAX as i64;

/// La longueur, en instructions d'eBPF, de la traduction d'un programme
/// vérifié (`bpf_convert_filter`). Une instruction classique en donne une à
/// dix-neuf (voir `longueur`), plus le prologue (A et X à zéro, le contexte
/// gardé : 3 ; et 4 de plus, la tête du paquet gardée en registres, si le
/// programme lit le paquet). Refusée (EINVAL) comme chez Linux, si un saut
/// ne tient pas sur 16 bits, en deux cas :
///   - la cible est à plus de 32767 instructions traduites ;
///   - le saut lui-même est au-delà de la 32768e : la traduction se fait en
///     deux passes, et dans la première les cibles en avant ne sont pas
///     encore placées (elles valent 0) : le saut paraît aller en arrière
///     d'autant, et Linux le refuse déjà (mesuré : `ja 0` derrière 2048
///     lectures longues, EINVAL ; derrière 2047, ENOMEM, la mémoire des
///     options pleine).
pub fn longueur_convertie(p: &[Instruction]) -> Result<usize, Refus> {
    let lit_le_paquet = p.iter().any(lit_le_paquet);
    // Le début de chaque instruction traduite (`addrs`).
    let mut debuts: Vec<u32> = remplie(p.len() + 1, 0).map_err(|_| Refus::Memoire)?;
    let mut n: u32 = 3 + if lit_le_paquet { 4 } else { 0 };
    for (i, ins) in p.iter().enumerate() {
        debuts[i] = n;
        n += longueur(ins);
    }
    debuts[p.len()] = n;
    for (i, ins) in p.iter().enumerate() {
        for (place, cible) in sauts(i, ins).into_iter().flatten() {
            let depuis = debuts[i] as i64 + place as i64 + 1;
            if depuis > -(i16::MIN as i64) || debuts[cible] as i64 - depuis > SAUT_MAX {
                return Err(Refus::Invalide);
            }
        }
    }
    Ok(n as usize)
}

/// Ce que le programme compte dans la mémoire des options de sa socket
/// (`bpf_prog_size`) : l'en-tête d'un `struct bpf_prog` (96 octets), puis 8
/// par instruction traduite. Mesuré pour chaque forme d'instruction (sonde
/// c10, c10e : `ret a` seul, 128 ; `ld [0]; ret a`, 264).
pub fn taille(longueur_convertie: usize) -> usize {
    96 + 8 * longueur_convertie
}

/// L'instruction lit-elle le paquet (`seen_ld_abs`) ? Une lecture ABS qui
/// n'est pas une extension, une lecture IND, et `ldx msh`.
fn lit_le_paquet(i: &Instruction) -> bool {
    let c = i.code;
    (c & 0x07 == LD && c & 0xe0 == ABS && extension(i.k).is_none()) || (c & 0x07 == LD && c & 0xe0 == IND) || c == LDX | B | MSH
}

/// La longueur de la traduction d'une instruction (vérifiée).
fn longueur(i: &Instruction) -> u32 {
    let c = i.code;
    match c & 0x07 {
        ALU if c == ALU | DIV | X || c == ALU | MOD | X => 5,
        ALU => 1,
        LD if c & 0xe0 == ABS => match extension(i.k) {
            Some(e) => longueur_extension(e),
            None => longueur_lecture(c & 0x18, i.k, false),
        },
        LD if c & 0xe0 == IND => longueur_lecture(c & 0x18, i.k, true),
        LDX if c == LDX | B | MSH => 1 + longueur_lecture(B, i.k, false) + 5,
        JMP if c == JMP | JA => 1,
        JMP => {
            // Une constante négative passe par un registre (une instruction de
            // plus) : les comparaisons d'eBPF étendent le signe de la leur.
            let par_registre = c & X == K && (i.k as i32) < 0;
            par_registre as u32 + sauts_conditionnels(c, i.jt, i.jf)
        }
        RET if c == RET | K => 2,
        _ => 1,
    }
}

/// Les sauts d'une comparaison traduite : un seul si l'une des branches est
/// l'instruction suivante (« si faux » ; « si vrai » pour JEQ, JGT et JGE,
/// dont l'eBPF a l'inverse : JNE, JLE, JLT, pas JSET), sinon deux (le saut
/// conditionnel, puis un JA).
fn sauts_conditionnels(code: u16, jt: u8, jf: u8) -> u32 {
    if jf == 0 || (jt == 0 && matches!(code & 0xf0, JEQ | JGT | JGE)) { 1 } else { 2 }
}

/// Les sauts de la traduction de l'instruction `i` (au plus deux) : leur
/// place dans sa traduction, et l'instruction classique visée.
fn sauts(i: usize, ins: &Instruction) -> [Option<(u32, usize)>; 2] {
    let c = ins.code;
    if c & 0x07 != JMP {
        return [None, None];
    }
    if c == JMP | JA {
        return [Some((0, i + 1 + ins.k as usize)), None];
    }
    let p = (c & X == K && (ins.k as i32) < 0) as u32;
    let (vrai, faux) = (i + 1 + ins.jt as usize, i + 1 + ins.jf as usize);
    if ins.jf == 0 {
        [Some((p, vrai)), None]
    } else if sauts_conditionnels(c, ins.jt, ins.jf) == 1 {
        [Some((p, faux)), None]
    } else {
        [Some((p, vrai)), Some((p + 1, faux))]
    }
}

/// La traduction d'une lecture du paquet (`convert_bpf_ld_abs`) : un chemin
/// rapide pour une lecture ABS à un décalage positif (la tête du paquet lue
/// directement : x86_64 lit sans alignement), puis l'appel d'une fonction
/// pour tout le reste.
fn longueur_lecture(taille: u16, k: u32, indirecte: bool) -> u32 {
    let decalage = k as i32;
    let mut n = 0;
    if !indirecte && decalage >= 0 {
        // mov, (sub si le décalage n'est pas nul), jslt, la lecture (directe
        // jusqu'à 32767 : sinon mov, add, puis elle), le boutisme (pas pour un
        // octet), ja.
        n += 1 + (decalage != 0) as u32 + 1 + if decalage <= i16::MAX as i32 { 1 } else { 3 } + (taille != B) as u32 + 1;
    }
    // Les trois premiers arguments, le quatrième (la constante ; ou X, plus
    // la constante si elle n'est pas nulle), l'appel, puis jsge, xor, exit.
    n + 3 + if indirecte { 1 + (k != 0) as u32 } else { 1 } + 1 + 3
}

/// La traduction d'une extension (`convert_bpf_extensions`), mesurée pour
/// chacune (sonde c10).
fn longueur_extension(e: Extension) -> u32 {
    match e {
        Extension::Protocole | Extension::Genre | Extension::VlanProtocole => 2,
        Extension::Interface { .. }
        | Extension::Attribut { .. }
        | Extension::Processeur
        | Extension::DecalageCharge
        | Extension::Hasard => 4,
        Extension::VlanPresent => 3,
        Extension::Marque | Extension::File | Extension::Hachage | Extension::XorX | Extension::VlanEtiquette => 1,
    }
}

/// La carte par laquelle un paquet est arrivé : son index (SKF_AD_IFINDEX)
/// et son type (SKF_AD_HATYPE : ARPHRD_ETHER 1, ARPHRD_LOOPBACK 772).
#[derive(Clone, Copy, Debug)]
pub struct Carte {
    pub index: u32,
    pub genre: u16,
}

/// Le paquet tel que le voit un filtre (le `sk_buff` de Linux, et ses
/// champs que lisent les extensions).
///
/// `octets` va du premier en-tête gardé (celui de liaison, ou de réseau) à
/// la fin des données ; `donnees` y est le début des données (`skb->data` :
/// l'en-tête de transport pour UDP, TCP et ping, le message pour AF_UNIX),
/// d'où comptent les décalages positifs, et `reseau` et `liaison` les deux
/// en-têtes (SKF_NET_OFF, SKF_LL_OFF ; sans en-tête de liaison, AF_UNIX,
/// une lecture SKF_LL_OFF échoue ; son « en-tête de réseau » est le début
/// du message, comme chez Linux, qui ne le pose jamais : mesuré).
///
/// Le paquet est toujours d'un seul tenant : chez Linux, les extensions
/// SKF_AD_NLATTR rendent 0 sur un `sk_buff` en morceaux (`skb_is_nonlinear` :
/// les données de TCP sont dans des pages à part, celles d'une carte au-delà
/// de 128 octets aussi) ; c'est une limite de sa disposition en mémoire, pas
/// une règle de l'extension. Nos paquets sont d'un seul tampon : la règle est
/// celle de Linux sur un paquet d'un seul tenant (UDP par lo : mesuré).
pub struct Vue<'a> {
    pub octets: &'a [u8],
    pub donnees: usize,
    pub reseau: usize,
    pub liaison: Option<usize>,
    /// Le protocole de la trame (`skb->protocol` : ETH_P_IP, 0x0800 ;
    /// AF_UNIX : 0).
    pub protocole: u16,
    /// PACKET_HOST (0), PACKET_BROADCAST (1), PACKET_MULTICAST (2),
    /// PACKET_LOOPBACK (5 : la copie d'une diffusion que nous avons envoyée).
    pub genre: u8,
    pub carte: Option<Carte>,
    pub marque: u32,
    /// La file de la carte (`queue_mapping`) : 1 pour la première file de
    /// réception d'une carte (`skb_record_rx_queue` : le numéro plus un) ; 0
    /// par lo.
    pub file: u16,
    /// Le hachage du flux (`skb->hash`).
    pub hachage: u32,
    /// Le processeur qui fait passer le paquet.
    pub processeur: u32,
    /// Où commence la charge, après l'en-tête de transport
    /// (`skb_get_poff`, compté depuis `donnees`).
    pub charge: u32,
}

impl Vue<'_> {
    /// `skb->len` : les données.
    fn longueur(&self) -> u32 {
        (self.octets.len() - self.donnees) as u32
    }

    /// Lit `taille` octets (1, 2, 4) au décalage `decalage` (ordre du
    /// réseau) : `bpf_skb_load_helper_convert_offset`, puis la lecture.
    /// None : hors du paquet (le programme rend 0). Un décalage négatif
    /// au-dessus de SKF_NET_OFF compte depuis l'en-tête de réseau : -8 n'est
    /// pas huit octets avant les données, mais 0xFFFF8 après l'en-tête IP
    /// (mesuré : hors du paquet).
    fn lire(&self, decalage: i32, taille: usize) -> Option<u32> {
        let debut = if decalage >= 0 {
            self.donnees as i64 + decalage as i64
        } else if decalage >= SKF_NET_OFF {
            self.reseau as i64 + (decalage - SKF_NET_OFF) as i64
        } else if decalage >= SKF_LL_OFF {
            self.liaison? as i64 + (decalage - SKF_LL_OFF) as i64
        } else {
            return None;
        };
        let debut = usize::try_from(debut).ok()?;
        let o = self.octets.get(debut..debut.checked_add(taille)?)?;
        Some(o.iter().fold(0, |v, &b| (v << 8) | b as u32))
    }
}

/// Exécute le programme `p` (vérifié) sur le paquet `v` : le nombre
/// d'octets à garder (`bpf_prog_run`), 0 pour le jeter.
pub fn executer(p: &[Instruction], v: &Vue, hasard: &mut dyn FnMut() -> u32) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut m = [0u32; MOTS];
    let mut pc = 0;
    loop {
        let Some(&i) = p.get(pc) else { return 0 };
        pc += 1;
        let c = i.code;
        let source = if c & X == X { x } else { i.k };
        match c & 0x07 {
            ALU => {
                a = match c & 0xf0 {
                    ADD => a.wrapping_add(source),
                    SUB => a.wrapping_sub(source),
                    MUL => a.wrapping_mul(source),
                    // La traduction : un diviseur nul fait rendre 0.
                    DIV => match a.checked_div(source) {
                        Some(q) => q,
                        None => return 0,
                    },
                    MOD => match a.checked_rem(source) {
                        Some(r) => r,
                        None => return 0,
                    },
                    OR => a | source,
                    AND => a & source,
                    XOR => a ^ source,
                    // Masqués à 31 bits (mesuré : 1 << 33 rend 2).
                    LSH => a.wrapping_shl(source),
                    RSH => a.wrapping_shr(source),
                    NEG => a.wrapping_neg(),
                    _ => return 0,
                };
            }
            LD | LDX => {
                let valeur = match c & 0xe0 {
                    IMM => i.k,
                    MEM => m[i.k as usize % MOTS],
                    LEN => v.longueur(),
                    MSH => match v.lire(i.k as i32, 1) {
                        Some(o) => (o & 0xf) << 2,
                        None => return 0,
                    },
                    ABS if c & 0x07 == LD && extension(i.k).is_some() => {
                        let Some(e) = extension(i.k) else { return 0 };
                        match valeur_extension(e, v, a, x, hasard) {
                            Some(val) => val,
                            None => return a,
                        }
                    }
                    ABS | IND => {
                        let decalage = (if c & 0xe0 == IND { x.wrapping_add(i.k) } else { i.k }) as i32;
                        let taille = match c & 0x18 {
                            W => 4,
                            H => 2,
                            _ => 1,
                        };
                        match v.lire(decalage, taille) {
                            Some(o) => o,
                            None => return 0,
                        }
                    }
                    _ => return 0,
                };
                if c & 0x07 == LD { a = valeur } else { x = valeur }
            }
            ST => m[i.k as usize % MOTS] = a,
            STX => m[i.k as usize % MOTS] = x,
            JMP => {
                let saut = if c == JMP | JA {
                    i.k as usize
                } else {
                    let vrai = match c & 0xf0 {
                        JEQ => a == source,
                        JGT => a > source,
                        JGE => a >= source,
                        JSET => a & source != 0,
                        _ => return 0,
                    };
                    (if vrai { i.jt } else { i.jf }) as usize
                };
                pc += saut;
            }
            RET => return if c == RET | A { a } else { i.k },
            _ => {
                if c == MISC | TAX {
                    x = a;
                } else if c == MISC | TXA {
                    a = x;
                }
            }
        }
    }
}

/// La valeur d'une extension ; None : la traduction sort du programme en
/// rendant A (SKF_AD_IFINDEX, SKF_AD_HATYPE sans carte).
fn valeur_extension(e: Extension, v: &Vue, a: u32, x: u32, hasard: &mut dyn FnMut() -> u32) -> Option<u32> {
    Some(match e {
        Extension::Protocole => v.protocole as u32,
        Extension::Genre => v.genre as u32 & 7,
        Extension::Interface { genre } => {
            let c = v.carte?;
            if genre { c.genre as u32 } else { c.index }
        }
        Extension::Attribut { imbrique } => attribut(v, a, x, imbrique),
        Extension::Marque => v.marque,
        Extension::File => v.file as u32,
        Extension::Hachage => v.hachage,
        Extension::Processeur => v.processeur,
        Extension::XorX => a ^ x,
        Extension::VlanEtiquette | Extension::VlanPresent | Extension::VlanProtocole => 0,
        Extension::DecalageCharge => v.charge,
        Extension::Hasard => hasard(),
    })
}

/// SKF_AD_NLATTR (`bpf_skb_get_nlattr`) : le premier attribut netlink de
/// type X dans les données, depuis le décalage A ; SKF_AD_NLATTR_NEST : dans
/// l'attribut qui est au décalage A. Son décalage depuis le début des
/// données, ou 0. Un attribut : sa longueur (16 bits, ordre de la machine,
/// en-tête de 4 octets compris), son type (les 14 bits bas), puis le suivant
/// à la longueur arrondie à 4 (`nla_ok`, `nla_next`, `nla_find`).
fn attribut(v: &Vue, a: u32, x: u32, imbrique: bool) -> u32 {
    let d = &v.octets[v.donnees..];
    let a = a as usize;
    if d.len() < 4 || a > d.len() - 4 {
        return 0;
    }
    let (debut, fin) = if imbrique {
        let l = u16::from_le_bytes([d[a], d[a + 1]]) as usize;
        if l < 4 || l > d.len() - a {
            return 0;
        }
        (a + 4, a + l)
    } else {
        (a, d.len())
    };
    let mut place = debut;
    let mut reste = (fin - debut) as i64;
    while reste >= 4 {
        let l = u16::from_le_bytes([d[place], d[place + 1]]) as i64;
        if l < 4 || l > reste {
            break;
        }
        if (u16::from_le_bytes([d[place + 2], d[place + 3]]) & 0x3fff) as u32 == x {
            return place as u32;
        }
        let pas = (l + 3) & !3;
        reste -= pas;
        place += pas as usize;
    }
    0
}

/// Les instructions de `octets` (le programme tel que l'a copié l'appel :
/// `Instruction::TAILLE` octets chacune).
pub fn decoder(octets: &[u8]) -> Result<Vec<Instruction>, Refus> {
    let mut p: Vec<Instruction> = avec_capacite(octets.len() / Instruction::TAILLE).map_err(|_| Refus::Memoire)?;
    for o in octets.chunks_exact(Instruction::TAILLE) {
        p.ajouter_dans_la_place(Instruction::lire([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]));
    }
    Ok(p)
}
