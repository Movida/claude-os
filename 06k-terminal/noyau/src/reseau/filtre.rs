//! Le filtre d'une socket (SO_ATTACH_FILTER) : un programme de BPF classique
//! (inet::filtre : sa vérification, sa mémoire, son interprète), posé sur la
//! socket, et passé sur chaque paquet qu'elle reçoit (`sk_filter_trim_cap`).
//!
//! Ce qu'il rend, `k` : 0 jette le paquet ; sinon, le paquet est coupé à
//! max(`cap`, k) octets, comptés depuis le début de ses données (`skb->data`),
//! `cap` étant ce qui ne se coupe jamais. Chaque protocole le passe à sa
//! place, sur ses données, et compte à sa façon ce qu'il jette (mesuré, sondes
//! c10c, c10d, c10e et c10g du lot 6 des soldes) :
//!   - UDP (udp.rs) : les données commencent à l'en-tête UDP, `cap` est sa
//!     longueur (8), la charge commence après lui ; un datagramme jeté compte
//!     une perte de la socket et une erreur d'UDP (InErrors) ;
//!   - ping (ping.rs) : à l'en-tête ICMP, `cap` 1, la charge à 8 ; jeté sans
//!     rien compter ;
//!   - TCP (tcp.rs) : à l'en-tête TCP, `cap` sa longueur, la charge après lui ;
//!     un segment jeté, une perte de la socket ; coupé, ses octets de trop
//!     reviennent par une retransmission ;
//!   - AF_UNIX en datagrammes et en paquets (unix.rs) : au message, `cap` 1 ;
//!     jeté, l'envoi réussit quand même ; pas de filtre pour un flux AF_UNIX
//!     (`unix_stream_sendmsg` ne l'appelle pas).
//!
//! Le filtre voit aussi, par des décalages négatifs, les en-têtes de réseau et
//! de liaison d'un paquet arrivé par IPv4 (paquet.rs, `pour_filtre`), et ce que
//! dit de lui le noyau, par les extensions : sa carte, son genre, son hachage,
//! sa marque (inet::filtre, `Vue`).

use super::interface::Interface;
use super::paquet::{self, Paquet};
use super::socket::{self, Socket};
use crate::partage::Arc;
use alloc::vec::Vec;
use inet::filtre::{self as cbpf, Carte, Instruction, Refus, Vue};

const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const ENOMEM: i64 = 12;
const EINVAL: i64 = 22;

/// Le protocole d'une trame IPv4 (`skb->protocol` : ETH_P_IP).
const ETH_P_IP: u16 = 0x0800;
/// Le type d'une carte (`dev->type`, SKF_AD_HATYPE) : Ethernet, et lo.
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;

/// Un filtre posé : son programme, vérifié, et ce qu'il compte dans la mémoire
/// des options de sa socket (inet::filtre, `taille`).
pub struct Filtre {
    programme: Vec<Instruction>,
    taille: usize,
}

impl Filtre {
    pub fn taille(&self) -> usize {
        self.taille
    }

    /// Le programme, tel que posé (SO_GET_FILTER le relit : Linux en garde
    /// la copie d'origine, `bpf_prog_store_orig_filter`, à côté de sa
    /// traduction).
    pub fn programme(&self) -> &[Instruction] {
        &self.programme
    }
}

/// Le filtre du programme `octets` (ses instructions telles que copiées du
/// programme, 8 octets chacune), dans l'ordre de `bpf_prepare_filter` : sa
/// vérification (EINVAL), puis sa traduction, dont un saut trop long pour elle
/// (EINVAL) ; plus de mémoire : ENOMEM.
pub fn faire(octets: &[u8]) -> Result<Arc<Filtre>, i64> {
    let refus = |r| match r {
        Refus::Invalide => -EINVAL,
        Refus::Memoire => -ENOMEM,
    };
    let programme = cbpf::decoder(octets).map_err(refus)?;
    cbpf::verifier(&programme).map_err(refus)?;
    let taille = cbpf::taille(cbpf::longueur_convertie(&programme).map_err(refus)?);
    Arc::new(Filtre { programme, taille }).map_err(|_| -ENOMEM)
}

/// `taille` octets de plus peuvent-ils entrer dans la mémoire des options d'une
/// socket qui en compte déjà `omem` (`sock_kmalloc`, `__sk_filter_charge`) ?
/// Strictement sous OPTMEM_MAX.
pub fn peut_compter(omem: usize, taille: usize) -> bool {
    taille <= socket::OPTMEM_MAX && omem + taille < socket::OPTMEM_MAX
}

/// Pose le filtre `f` sur la socket `s` (`__sk_attach_prog`), à la place de
/// l'ancien : compté dans la mémoire des options AVANT que l'ancien n'en sorte
/// (mesuré : remplacer un filtre de 130976 octets par un de 264 : ENOMEM,
/// l'ancien encore compté), sinon ENOMEM. Le verrou (SO_LOCK_FILTER) est vu
/// avant, par l'appelant (`__get_filter` : EPERM avant tout le reste). Sous le
/// `Mutex` des appels de `s` (le `lock_sock` de Linux), que tiennent aussi les
/// adhésions à des groupes (multidiffusion.rs), qui comptent dans la même
/// mémoire : l'une ne passe pas entre le compte de l'autre et son ajout.
pub fn attacher(s: &Socket, f: Arc<Filtre>) -> Result<(), i64> {
    if !peut_compter(s.memoire_des_options(), f.taille) {
        return Err(-ENOMEM);
    }
    // L'ancien est rendu hors du verrou.
    let ancien = s.filtre.verrouiller().replace(f);
    drop(ancien);
    Ok(())
}

/// SO_DETACH_FILTER (`sk_detach_filter`) : verrouillé, EPERM ; sans filtre,
/// ENOENT. Sous le `Mutex` des appels, comme `attacher`.
pub fn detacher(s: &Socket) -> Result<(), i64> {
    if s.drapeau(socket::FILTRE_VERROUILLE) {
        return Err(-EPERM);
    }
    let ancien = s.filtre.verrouiller().take();
    if ancien.is_none() {
        return Err(-ENOENT);
    }
    Ok(())
}

/// Le filtre de `s`, s'il en a un : une référence, prise sous son verrou.
pub fn de(s: &Socket) -> Option<Arc<Filtre>> {
    s.filtre.verrouiller().clone()
}

/// Ce que fait un filtre d'un paquet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Jeter,
    /// Garder les n premiers octets des données (au moins `cap` ; plus que la
    /// longueur : rien n'est coupé).
    Garder(usize),
}

/// Passe le filtre `f` sur le paquet vu par `v` (`sk_filter_trim_cap`), `cap`
/// octets ne se coupant pas.
pub fn passer(f: &Filtre, v: &Vue, cap: usize) -> Verdict {
    match cbpf::executer(&f.programme, v, &mut crate::aleatoire::u32) {
        0 => Verdict::Jeter,
        k => Verdict::Garder(cap.max(k as usize)),
    }
}

/// La carte `i` telle que la voit un filtre : son index, son type.
pub fn carte(i: &Interface) -> Carte {
    Carte { index: i.index, genre: if i.boucle() { ARPHRD_LOOPBACK } else { ARPHRD_ETHER } }
}

/// Passe le filtre `f` sur le paquet `p` arrivé par IPv4 par la carte `carte`,
/// l'en-tête de transport (`recul` octets) déjà retiré de ses données : ses
/// données commencent à cet en-tête, et sa charge `charge` octets plus loin
/// (`skb_get_poff`, SKF_AD_PAY_OFFSET). Ce que disent ses extensions : ETH_P_IP ;
/// son genre, sa marque et son hachage (paquet.rs, `Contexte`) ; la file 1 d'une
/// carte (`skb_record_rx_queue` de virtio_net : le numéro de la file, plus un),
/// 0 par lo et pour la copie d'une diffusion que nous avons envoyée (`netif_rx`
/// ne la note pas) ; le processeur qui le fait passer.
pub fn passer_ip(f: &Filtre, p: &Paquet, recul: usize, cap: usize, carte: Carte, charge: u32) -> Verdict {
    // Un paquet arrivé par IPv4 a toujours ses en-têtes notés, et son en-tête de
    // transport juste avant ses données (ipv4.rs) : sans eux, ce serait une
    // faute du noyau, et un filtre ne laisse pas passer ce qu'il n'a pas vu.
    match vue_ip(p, recul, carte, |_| charge) {
        Some(v) => passer(f, &v, cap),
        None => Verdict::Jeter,
    }
}

/// Le paquet `p` arrivé par IPv4 par la carte `carte`, tel que le voit un
/// programme, ses données reculées de `recul` octets (voir `passer_ip`) ;
/// `charge` : où commence sa charge, d'après ses données.
fn vue_ip(p: &Paquet, recul: usize, carte: Carte, charge: impl FnOnce(&[u8]) -> u32) -> Option<Vue<'_>> {
    let (octets, donnees, reseau, liaison) = p.pour_filtre(recul)?;
    let c = p.contexte();
    Some(Vue {
        octets, donnees, reseau, liaison, protocole: ETH_P_IP, genre: c.genre, carte: Some(carte), marque: c.marque,
        file: (carte.genre == ARPHRD_ETHER && c.genre != paquet::BOUCLE) as u16, hachage: c.hachage,
        processeur: crate::processeur::numero(), charge: charge(&octets[donnees..]),
    })
}

/// Le programme d'un groupe SO_REUSEPORT (SO_ATTACH_REUSEPORT_CBPF,
/// inet::groupes) sur le paquet `p` arrivé par IPv4 par la carte `carte` :
/// l'index qu'il rend (`run_bpf_filter`). Linux retire l'en-tête de
/// transport le temps du programme (`pskb_pull(skb, hdr_len)`) : ses données
/// commencent après lui, comme celles de `p` (son en-tête de transport, de
/// `entete` octets, déjà retiré), et ses en-têtes de réseau et de liaison se
/// lisent toujours (mesuré, sonde c10f du lot 6 des soldes). Ce qu'il voit
/// d'autre est ce que voit un filtre (`passer_ip`), sauf sa charge
/// (SKF_AD_PAY_OFFSET, `skb_get_poff`) : le dissecteur de Linux part de
/// l'en-tête de réseau, AVANT les données, et compte le début du transport
/// en 16 bits sans signe, borné par la longueur des données (`min_t(u16,
/// nhoff, skb->len)` : -8 devient 65 528, au-delà de toute longueur) ; la
/// charge commence donc 8 octets après la fin d'un datagramme UDP (mesuré :
/// 28 pour 20 octets), et à la fin d'un segment TCP (dont l'en-tête se lirait
/// 12 octets plus loin, hors du paquet : 0 pour un SYN, mesuré). `tcp` : le
/// paquet est un segment TCP. Un paquet sans ses en-têtes notés (jamais, voir
/// `passer_ip`) rend un index trop grand : le hachage choisit.
pub fn index_ip(f: &Filtre, p: &Paquet, entete: usize, tcp: bool, carte: Carte) -> u32 {
    let charge = |donnees: &[u8]| {
        let debut = (entete as u16).wrapping_neg().min(donnees.len() as u16) as u32;
        match (tcp, donnees.get(debut as usize + 12)) {
            (true, Some(&doff)) => debut + 20.max((doff as u32 & 0xF0) >> 2),
            (true, None) => debut,
            (false, _) => debut + 8,
        }
    };
    match vue_ip(p, 0, carte, charge) {
        Some(v) => cbpf::executer(&f.programme, &v, &mut crate::aleatoire::u32),
        None => u32::MAX,
    }
}

/// Passe le filtre `f` sur le message `octets` d'AF_UNIX : ses données sont le
/// message, qui n'a ni en-tête de liaison (une lecture SKF_LL_OFF échoue), ni de
/// réseau (SKF_NET_OFF lit le message : Linux ne le pose jamais, et il vaut le
/// début des données, mesuré), ni carte (les extensions qui en lisent une
/// rendent A tel quel), ni protocole, ni marque, ni hachage ; sa charge commence
/// au début (SKF_AD_PAY_OFFSET : 0, mesuré). `cap` : 1.
pub fn passer_unix(f: &Filtre, octets: &[u8]) -> Verdict {
    let v = Vue {
        octets, donnees: 0, reseau: 0, liaison: None, protocole: 0, genre: paquet::HOTE, carte: None, marque: 0, file: 0,
        hachage: 0, processeur: crate::processeur::numero(), charge: 0,
    };
    passer(f, &v, 1)
}
