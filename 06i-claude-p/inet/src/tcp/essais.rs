//! Pour les tests internes des modules de TCP : une charge, une connexion établie, des segments
//! en vol. Ces tests regardent l'état de la connexion, et posent eux-mêmes les cas limites ; les
//! valeurs attendues viennent des formules de Linux (citées), pas de notre code.

use super::*;
use alloc::vec;

/// La taille qu'une charge de test refuse de créer : la mémoire qui manque, à l'endroit voulu.
pub(super) const REFUSEE: usize = 777;

/// Une charge de test.
pub(super) struct Octets(pub Vec<u8>, pub usize, pub usize);

impl Charge for Octets {
    fn octets(&self) -> &[u8] {
        &self.0[self.1..]
    }
    fn avancer(&mut self, n: usize) {
        self.1 = (self.1 + n).min(self.0.len());
    }
    fn taille_vraie(&self) -> usize {
        self.2
    }
    fn neuve(n: usize) -> Option<Octets> {
        if n == REFUSEE {
            return None;
        }
        Some(Octets(Vec::with_capacity(n), 0, 96 + n + 576))
    }
    fn completer(&mut self, o: &[u8]) {
        self.0.extend_from_slice(o);
    }
}

/// Une charge de `n` octets, de taille vraie `vraie`.
pub(super) fn octets(n: usize, vraie: usize) -> Octets {
    Octets(vec![7; n], 0, vraie)
}

pub(super) type C = Tcb<Octets>;

pub(super) const MSS: u32 = 1000;
pub(super) const ISS: u32 = 7000;
pub(super) const HEURE: u64 = 7_000_000_000;
pub(super) const MS: u64 = 1_000_000;

/// Une connexion établie, sans horodatages ni échelle, la fenêtre de l'autre large, la cwnd large.
pub(super) fn etablie(sack: bool) -> C {
    let syn = Tcp {
        source: 40000, destination: 80, seq: 1000, drapeaux: tcp::SYN, fenetre: 65535,
        options: tcp::Options { mss: Some(MSS as u16), sack_permis: sack, ..tcp::Options::default() },
        ..Tcp::default()
    };
    let mut c: C = Tcb::depuis_syn(&syn, ISS, MSS as u16, 131_072, 1 << 22, 0);
    c.emettre(HEURE, |_| {});
    let ack = Tcp { seq: 1001, ack: ISS + 1, drapeaux: tcp::ACK, fenetre: 65535, options: tcp::Options::default(), ..syn };
    c.recevoir(&ack, octets(0, 0), HEURE);
    assert_eq!(c.etat(), Etat::Etablie);
    assert_eq!(c.sack_ok, sack);
    // Sans la mesure de la poignée de main : chaque test pose la sienne.
    c.rtt = rtt::Rtt::new();
    c.min_rtt = minmax::MinMax::new();
    c.cc.cwnd = 1000;
    c.snd_wnd = 1 << 24;
    c
}

/// `n` segments d'un MSS en vol, partis à `HEURE`.
pub(super) fn en_vol(c: &mut C, n: usize) {
    c.reglages.nodelay = true;
    let a = c.ecrire::<()>(n * MSS as usize, |d| {
        d.fill(1);
        Ok(())
    });
    assert_eq!(a, Ok(n * MSS as usize));
    c.emettre(HEURE, |_| {});
    assert_eq!(c.file.len(), n);
}

/// La fin du segment `i` (compté depuis 0) d'une connexion de `etablie`.
pub(super) fn fin(i: u32) -> u32 {
    ISS + 1 + (i + 1) * MSS
}

/// Le début du segment `i`.
pub(super) fn debut(i: u32) -> u32 {
    ISS + 1 + i * MSS
}

/// Une fille en SYN_RECEIVED, son SYN-ACK parti.
pub(super) fn fille(ts: bool) -> C {
    let syn = Tcp {
        source: 40000, destination: 80, seq: 1000, drapeaux: tcp::SYN, fenetre: 65535,
        options: tcp::Options { mss: Some(MSS as u16), sack_permis: true, horodatage: ts.then_some((500, 0)), ..tcp::Options::default() },
        ..Tcp::default()
    };
    let mut c: C = Tcb::depuis_syn(&syn, ISS, MSS as u16, 131_072, 1 << 22, 0);
    c.emettre(HEURE, |_| {});
    assert_eq!(c.etat(), Etat::SynRecu);
    c
}

/// Une connexion en SYN_SENT, son SYN parti.
pub(super) fn syn_envoye() -> C {
    let mut c: C = Tcb::connecter(80, 40000, ISS, MSS as u16, 131_072, 1 << 22, 0);
    c.emettre(HEURE, |_| {});
    c
}
