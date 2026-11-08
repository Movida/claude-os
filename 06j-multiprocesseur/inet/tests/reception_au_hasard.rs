//! La réception, au hasard, contre ses invariants : des segments autour de ce qui est attendu
//! (en retard, à cheval, hors d'ordre, avec ou sans horodatages, SACK et échelle), un programme
//! qui lit, le temps, la mémoire qui se tend. À chaque pas : le flux lu est juste, `lisibles` suit
//! RCV.NXT, la mémoire reste bornée par SO_RCVBUF, et le bord droit annoncé ne recule jamais
//! (`tcp_select_window`), sauf une fenêtre nulle faute de mémoire (ICSK_ACK_NOMEM).

use formats::reseau::tcp::{self, Options, Tcp};
use inet::tcp::{self as t, Charge, Etat, Sortant, Tcb};

/// Le surcoût d'un paquet, comme dans le noyau.
const SURCOUT: usize = 576;

#[derive(Debug)]
struct K {
    b: Vec<u8>,
    d: usize,
    cap: usize,
}

impl Charge for K {
    fn octets(&self) -> &[u8] {
        &self.b[self.d..]
    }
    fn avancer(&mut self, n: usize) {
        self.d = (self.d + n).min(self.b.len());
    }
    fn taille_vraie(&self) -> usize {
        self.cap + SURCOUT
    }
    fn neuve(n: usize) -> Option<K> {
        Some(K { b: Vec::with_capacity(n), d: 0, cap: 96 + n })
    }
    fn completer(&mut self, o: &[u8]) {
        self.b.extend_from_slice(o);
    }
}

fn charge(o: Vec<u8>) -> K {
    let cap = o.len() + 54;
    K { b: o, d: 0, cap }
}

struct Hasard(u64);

impl Hasard {
    fn n(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn sous(&mut self, m: u64) -> u64 {
        self.n() % m.max(1)
    }
}

/// L'octet à la place `decalage` du flux : un octet faux se voit.
fn octet(decalage: u32) -> u8 {
    (decalage.wrapping_mul(31) ^ (decalage >> 8)) as u8
}

fn sortants(c: &mut Tcb<K>, h: u64) -> Vec<Tcp> {
    let mut s: Vec<Sortant> = Vec::new();
    c.emettre(h, |x| s.push(x));
    s.into_iter().map(|x| x.entete).collect()
}

fn essai(graine: u64) {
    let mut r = Hasard(graine.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut h: u64 = 1_000_000_000;
    let isn: u32 = r.n() as u32;
    let echelle_lui = if r.sous(2) == 0 { Some(7u8) } else { None };
    let notre_echelle = r.sous(10) as u8;
    let sack = r.sous(2) == 0;
    let ts = r.sous(2) == 0;
    let rcvbuf = [4_096usize, 16_384, 65_536, 131_072, 1_000_000][r.sous(5) as usize];
    let opt = Options { mss: Some(1460), echelle: echelle_lui, horodatage: ts.then_some((5, 0)), sack_permis: sack, ..Options::default() };
    let syn = Tcp { source: 40000, destination: 80, seq: isn, drapeaux: tcp::SYN, fenetre: 65535, options: opt, ..Tcp::default() };
    let mut f: Tcb<K> = Tcb::depuis_syn(&syn, 7000, 1460, rcvbuf, 16_384, notre_echelle);
    f.rcvbuf_fixe = r.sous(2) == 0;
    f.rcvbuf_max = 6 << 20;
    f.attachee = r.sous(4) != 0;
    let sa = sortants(&mut f, h);
    assert_eq!(sa.len(), 1);
    let mut tsval = 100u32;
    let tsopt = |v: u32, e: u32| Options { horodatage: ts.then_some((v, e)), ..Options::default() };
    let ecr0 = sa[0].options.horodatage.map_or(0, |x| x.0);
    let ack = Tcp { source: 40000, destination: 80, seq: isn.wrapping_add(1), ack: 7001, drapeaux: tcp::ACK, fenetre: 1000, options: tsopt(tsval, ecr0), ..Tcp::default() };
    f.recevoir(&ack, charge(Vec::new()), h);
    assert_eq!(f.etat(), Etat::Etablie, "graine {graine}");
    let e = if echelle_lui.is_some() { notre_echelle as u32 } else { 0 };
    let base = isn.wrapping_add(1);
    let mut bord = base.wrapping_add(sa[0].fenetre as u32);
    let mut lu = 0u32;
    let niveaux = [t::Memoire::Libre, t::Memoire::Souple, t::Memoire::Pression, t::Memoire::Excedent, t::Memoire::Limite];
    let pression = r.sous(3) == 0;
    let mut ecr = ecr0;
    for pas in 0..20_000u32 {
        match r.sous(100) {
            0..=69 => {
                // Un segment : autour de ce qui est attendu.
                let nxt = f.numeros().2;
                let fen = f.fenetre_annoncee() as u64;
                let debut = match r.sous(10) {
                    0 => nxt.wrapping_sub(r.sous(3000) as u32),
                    1 | 2 => nxt.wrapping_add(r.sous(1 + fen + 200) as u32),
                    _ => nxt,
                };
                let n = match r.sous(5) {
                    0 => 1 + r.sous(40),
                    1 => 1 + r.sous(300),
                    2 => 1460,
                    _ => 1 + r.sous(1460),
                } as u32;
                let o: Vec<u8> = (0..n).map(|i| octet(debut.wrapping_add(i).wrapping_sub(base))).collect();
                tsval = tsval.wrapping_add(r.sous(3) as u32);
                let drapeaux = tcp::ACK | if r.sous(4) == 0 { tcp::PSH } else { 0 };
                let hd = Tcp { source: 40000, destination: 80, seq: debut, ack: 7001, drapeaux, fenetre: 1000, options: tsopt(tsval, ecr), ..Tcp::default() };
                f.recevoir(&hd, charge(o), h);
            }
            70..=84 => {
                // Le programme lit.
                let k = 1 + r.sous(17);
                let n = 1 + r.sous(1 << k) as usize;
                let mut v: Vec<u8> = Vec::new();
                f.lire::<()>(n, false, |m| {
                    v.extend_from_slice(m);
                    Ok(m.len())
                })
                .unwrap();
                for (k, o) in v.iter().enumerate() {
                    assert_eq!(*o, octet(lu.wrapping_add(k as u32)), "graine {graine} pas {pas} : un octet faux");
                }
                lu = lu.wrapping_add(v.len() as u32);
                f.lu(v.len(), h);
            }
            85..=89 => {
                h += r.sous(5_000_000);
                f.minuteur(h);
            }
            90..=94 if pression => f.memoire = niveaux[r.sous(5) as usize],
            _ => h += r.sous(50_000),
        }
        let nxt = f.numeros().2;
        assert_eq!(f.lisibles() as u32, nxt.wrapping_sub(base.wrapping_add(lu)), "graine {graine} pas {pas} : lisibles et RCV.NXT");
        // La mémoire ne dépasse SO_RCVBUF que de quoi loger un paquet (une file vide en prend
        // toujours un).
        let plafond = f.rcvbuf + 1460 + 54 + SURCOUT + 1460;
        assert!(f.memoire_reception() <= plafond || f.lisibles() <= 1460 || !matches!(f.memoire, t::Memoire::Libre),
                "graine {graine} pas {pas} : memoire {} rcvbuf {}", f.memoire_reception(), f.rcvbuf);
        for s in sortants(&mut f, h) {
            ecr = s.options.horodatage.map_or(ecr, |x| x.0);
            let droit = s.ack.wrapping_add((s.fenetre as u32) << e);
            if s.fenetre == 0 {
                bord = droit;
                continue;
            }
            assert!(!t::avant(droit, bord), "graine {graine} pas {pas} : le bord droit recule de {} (fenetre {}, echelle {e})", bord.wrapping_sub(droit), s.fenetre);
            bord = droit;
        }
    }
    // Tout lire : la file de lecture, vide, ne compte plus rien.
    let mut v: Vec<u8> = Vec::new();
    f.lire::<()>(usize::MAX >> 1, false, |m| {
        v.extend_from_slice(m);
        Ok(m.len())
    })
    .unwrap();
    for (k, o) in v.iter().enumerate() {
        assert_eq!(*o, octet(lu.wrapping_add(k as u32)), "graine {graine} : un octet faux a la fin");
    }
    assert_eq!(f.memoire_reception(), f.memoire_hors_ordre(), "graine {graine} : la file de lecture, vide, compte encore");
}

#[test]
fn au_hasard() {
    let n: u64 = std::env::var("RECEPTION_ESSAIS").ok().and_then(|x| x.parse().ok()).unwrap_or(100);
    for g in 1..=n {
        essai(g);
    }
}
