//! Le texte de /proc/net/snmp (inet::snmp), comparé à celui de Linux 6.18
//! (`cat /proc/net/snmp` sur l'hôte : les noms, au caractère près) ; et ce
//! que comptent les connexions de TCP (inet::tcp).

use formats::reseau::tcp::{self as ftcp, Tcp as Entete};
use inet::snmp::{Icmp, Ip, Mib, Tcp, Udp};
use inet::tcp::{Charge, Compte, Etat, Sortant, Tcb};

fn texte(m: &Mib) -> String {
    let mut t = String::new();
    m.ecrire(64, &mut t).unwrap();
    t
}

const IP: &str = "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits\n";
const ICMP: &str = "Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n";
const TCP: &str = "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n";
const UDP: &str = "InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n";

fn zeros(n: usize) -> String {
    " 0".repeat(n)
}

/// À zéro : IcmpMsg absent, les quatre valeurs fixes de TCP (MaxConn signé).
#[test]
fn a_zero() {
    static M: Mib = Mib::new();
    let attendu = format!(
        "{IP}Ip: 2 64{}\n{ICMP}Icmp:{}\n{TCP}Tcp: 1 200 120000 -1{}\nUdp: {UDP}Udp:{}\nUdpLite: {UDP}UdpLite:{}\n",
        zeros(18), zeros(29), zeros(11), zeros(9), zeros(9)
    );
    assert_eq!(texte(&M), attendu);
}

/// Chaque compteur à sa place ; les genres ICMP de la MIB lus dans IcmpMsg ;
/// IcmpMsg par paires de lignes de seize, les reçus puis les envoyés.
#[test]
fn les_places() {
    static M: Mib = Mib::new();
    M.ip(Ip::InReceives);
    M.ip(Ip::OutTransmits);
    M.ip(Ip::OutTransmits);
    M.icmp(Icmp::InCsumErrors);
    M.icmp(Icmp::OutRateLimitHost);
    M.udp(Udp::MemErrors);
    // Dix-sept genres reçus, de 0 à 16 ; deux envois d'un écho (8).
    for g in 0..17 {
        M.icmp_entree(g);
    }
    M.icmp_sortie(8);
    M.icmp_sortie(8);
    let t = texte(&M);
    let lignes: Vec<&str> = t.lines().collect();
    assert_eq!(lignes[1], format!("Ip: 2 64 1{} 2", zeros(16)));
    // InMsgs InErrors InCsumErrors, les entrées par genre (3, 11, 12, 4, 5, 8,
    // 0, 13, 14, 17, 18), OutMsgs OutErrors et les limites, les sorties.
    assert_eq!(lignes[3], "Icmp: 0 0 1 1 1 1 1 1 1 1 1 1 0 0 2 0 0 1 0 0 0 0 0 2 0 0 0 0 0");
    let noms: String = (0..16).map(|g| format!(" InType{g}")).collect();
    assert_eq!(lignes[4], format!("IcmpMsg:{noms}"));
    assert_eq!(lignes[5], format!("IcmpMsg:{}", " 1".repeat(16)));
    assert_eq!(lignes[6], "IcmpMsg: InType16 OutType8");
    assert_eq!(lignes[7], "IcmpMsg: 1 2");
    assert_eq!(lignes[8], TCP.trim_end());
    assert_eq!(lignes[11], format!("Udp:{} 1", zeros(8)));
    assert_eq!(lignes.len(), 14);
    assert!(t.ends_with('\n'));
}

// --- Les compteurs de TCP tenus par la connexion (inet::tcp) ---

struct Octets(Vec<u8>);

impl Charge for Octets {
    fn octets(&self) -> &[u8] {
        &self.0
    }
    fn avancer(&mut self, n: usize) {
        self.0.drain(..n.min(self.0.len()));
    }
    fn taille_vraie(&self) -> usize {
        2 * self.0.len() + 64
    }
    fn neuve(n: usize) -> Option<Octets> {
        Some(Octets(Vec::with_capacity(n)))
    }
    fn completer(&mut self, o: &[u8]) {
        self.0.extend_from_slice(o);
    }
}

type C = Tcb<Octets>;

/// L'heure des essais : une connexion prend 0 pour « aucune heure ».
const T0: u64 = 7_000_000_000;

/// Ce que `c` envoie à l'heure `t` : les en-têtes, et ce que chacun compte.
fn sortis(c: &mut C, t: u64) -> Vec<(Entete, Compte)> {
    let mut s: Vec<Sortant> = Vec::new();
    c.emettre(t, |x| s.push(x));
    s.into_iter().map(|x| (x.entete, x.compte)).collect()
}

fn recevoir(c: &mut C, h: &Entete, t: u64) {
    c.recevoir(h, Octets(Vec::new()), t);
}

/// Un client en SYN_SENT et la fille qu'il fait naître, établis tous deux.
fn poignee(m: &'static Mib) -> (C, C) {
    let mut c = C::connecter(m, 40000, 80, 1000, 1460, 131_072, 16_384, 7);
    let s = sortis(&mut c, T0);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].1, Compte::Neuf);
    let mut f = C::depuis_syn(m, &s[0].0, 7000, 1460, 131_072, 16_384, 7);
    let s = sortis(&mut f, T0);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].1, Compte::SynAck { renvoi: false });
    recevoir(&mut c, &s[0].0, T0);
    assert_eq!(c.etat(), Etat::Etablie);
    let s = sortis(&mut c, T0);
    assert_eq!(s.iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Neuf]);
    recevoir(&mut f, &s[0].0, T0);
    assert_eq!(f.etat(), Etat::Etablie);
    (c, f)
}

fn tcp(m: &Mib) -> [u64; 4] {
    [m.valeur_tcp(Tcp::ActiveOpens), m.valeur_tcp(Tcp::PassiveOpens), m.valeur_tcp(Tcp::AttemptFails), m.valeur_tcp(Tcp::EstabResets)]
}

/// Un connect refusé par un RST : une ouverture active, une tentative ratée.
#[test]
fn connexion_refusee() {
    static M: Mib = Mib::new();
    let mut c = C::connecter(&M, 40000, 81, 5, 1460, 131_072, 16_384, 7);
    let s = sortis(&mut c, T0);
    let rst = Entete { seq: 0, ack: s[0].0.seq + 1, drapeaux: ftcp::RST | ftcp::ACK, ..s[0].0 };
    let rst = Entete { source: s[0].0.destination, destination: s[0].0.source, options: Default::default(), ..rst };
    recevoir(&mut c, &rst, T0);
    assert_eq!(c.etat(), Etat::Fermee);
    assert_eq!(tcp(&M), [1, 0, 1, 0]);
    assert_eq!(M.valeur_tcp(Tcp::CurrEstab), 0);
}

/// La poignée de main, puis l'un coupe (SO_LINGER à 0) : chacun compte une
/// connexion établie, puis une fin brutale ; la jauge redescend à zéro.
#[test]
fn etablies_puis_coupees() {
    static M: Mib = Mib::new();
    let (mut c, mut f) = poignee(&M);
    assert_eq!(tcp(&M), [1, 1, 0, 0]);
    assert_eq!(M.valeur_tcp(Tcp::CurrEstab), 2);
    c.avorter();
    assert_eq!(M.valeur_tcp(Tcp::CurrEstab), 1);
    let s = sortis(&mut c, T0);
    assert_eq!((s.len(), s[0].1), (1, Compte::Coupure));
    recevoir(&mut f, &s[0].0, T0);
    assert_eq!(f.etat(), Etat::Fermee);
    assert_eq!(tcp(&M), [1, 1, 0, 2]);
    assert_eq!(M.valeur_tcp(Tcp::CurrEstab), 0);
}

/// Une connexion rendue encore établie redescend la jauge (le filet de Drop).
#[test]
fn rendue_etablie() {
    static M: Mib = Mib::new();
    let (c, f) = poignee(&M);
    drop(c);
    assert_eq!(M.valeur_tcp(Tcp::CurrEstab), 1);
    drop(f);
    assert_eq!(M.valeur_tcp(Tcp::CurrEstab), 0);
}

/// Le SYN renvoyé à l'échéance du RTO compte dans RetransSegs, et pas dans
/// OutSegs ; un SYN-ACK renvoyé, dans les deux (`tcp_rtx_synack`).
#[test]
fn renvois_du_syn() {
    static M: Mib = Mib::new();
    let mut c = C::connecter(&M, 40000, 80, 1000, 1460, 131_072, 16_384, 7);
    let s = sortis(&mut c, T0);
    let t = c.echeance().unwrap();
    c.minuteur(t);
    assert_eq!(sortis(&mut c, t).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Renvoi]);

    let mut f = C::depuis_syn(&M, &s[0].0, 7000, 1460, 131_072, 16_384, 7);
    assert_eq!(sortis(&mut f, T0)[0].1, Compte::SynAck { renvoi: false });
    // Le même SYN revient : le SYN-ACK s'est perdu.
    recevoir(&mut f, &s[0].0, T0 + 1000);
    assert_eq!(sortis(&mut f, T0 + 1000).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::SynAck { renvoi: true }]);
    let t = f.echeance().unwrap();
    f.minuteur(t);
    assert_eq!(sortis(&mut f, t).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::SynAck { renvoi: true }]);
}

/// Des données renvoyées par le RTO : Renvoi ; un SYN dans une connexion
/// établie : l'ACK de défi, et une erreur reçue.
#[test]
fn renvoi_et_defi() {
    static M: Mib = Mib::new();
    let (mut c, mut f) = poignee(&M);
    c.ecrire::<()>(100, |d| {
        d.fill(7);
        Ok(())
    })
    .unwrap();
    let s = sortis(&mut c, T0);
    assert_eq!(s.iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Neuf]);
    let t = c.echeance().unwrap();
    c.minuteur(t);
    assert_eq!(sortis(&mut c, t).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Renvoi]);

    let syn = Entete { drapeaux: ftcp::SYN, ack: 0, ..s[0].0 };
    recevoir(&mut f, &syn, t);
    assert_eq!(M.valeur_tcp(Tcp::InErrs), 1);
    assert_eq!(sortis(&mut f, t).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Neuf]);
}

/// Une fille qui meurt en SYN_RECEIVED : ses SYN-ACK épuisés, sans ouverture ratée
/// (`reqsk_timer_handler` : une simple demande, qui meurt en silence) ; un RST dans sa
/// fenêtre, une (`tcp_check_req`).
#[test]
fn filles_qui_meurent() {
    static M: Mib = Mib::new();
    let syn = Entete { source: 40000, destination: 80, seq: 1000, drapeaux: ftcp::SYN, fenetre: 65535, ..Entete::default() };
    let mut f = C::depuis_syn(&M, &syn, 7000, 1460, 131_072, 16_384, 7);
    sortis(&mut f, T0);
    for _ in 0..20 {
        let t = f.echeance().unwrap();
        f.minuteur(t);
        sortis(&mut f, t);
        if f.etat() != Etat::SynRecu {
            break;
        }
    }
    assert_eq!(f.etat(), Etat::Fermee);
    assert_eq!(tcp(&M), [0, 0, 0, 0]);
    let mut f = C::depuis_syn(&M, &syn, 7000, 1460, 131_072, 16_384, 7);
    sortis(&mut f, T0);
    recevoir(&mut f, &Entete { seq: 1001, drapeaux: ftcp::RST, ..syn }, T0);
    assert_eq!(f.etat(), Etat::Fermee);
    assert_eq!(tcp(&M), [0, 0, 1, 0]);
}

/// Un SYN hors d'ESTABLISHED (CLOSE_WAIT, FIN_WAIT_2) : l'ACK de défi part, mais rien ne
/// compte dans InErrs (`tcp_rcv_state_process` : `tcp_validate_incoming(..., 0)`).
#[test]
fn defi_hors_d_etablie() {
    static M: Mib = Mib::new();
    let (mut c, mut f) = poignee(&M);
    c.fermer_envoi();
    let fin = sortis(&mut c, T0);
    recevoir(&mut f, &fin[0].0, T0);
    assert_eq!(f.etat(), Etat::AttenteFermeture);
    // L'ACK du FIN attend (le mode « ping-pong » de `tcp_fin`) : son échéance.
    assert!(sortis(&mut f, T0).is_empty());
    let t = f.echeance().unwrap();
    f.minuteur(t);
    let ack = sortis(&mut f, t);
    recevoir(&mut c, &ack[0].0, t);
    assert_eq!(c.etat(), Etat::FinAttente2);
    recevoir(&mut f, &Entete { drapeaux: ftcp::SYN, ack: 0, ..fin[0].0 }, t + 1000);
    assert_eq!(sortis(&mut f, t + 1000).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Neuf]);
    recevoir(&mut c, &Entete { drapeaux: ftcp::SYN, ack: 0, ..ack[0].0 }, t + 1000);
    assert_eq!(sortis(&mut c, t + 1000).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Neuf]);
    assert_eq!(M.valeur_tcp(Tcp::InErrs), 0);
}

/// L'ouverture simultanée : le premier SYN-ACK ne compte nulle part (SND.NXT
/// l'a déjà dépassé), celui que renvoie le RTO dans RetransSegs.
#[test]
fn ouverture_simultanee() {
    static M: Mib = Mib::new();
    let mut a = C::connecter(&M, 1, 2, 100, 1460, 131_072, 16_384, 7);
    let mut b = C::connecter(&M, 2, 1, 900, 1460, 131_072, 16_384, 7);
    let sa = sortis(&mut a, T0);
    let _ = sortis(&mut b, T0);
    recevoir(&mut b, &sa[0].0, T0);
    assert_eq!(b.etat(), Etat::SynRecu);
    assert_eq!(sortis(&mut b, T0).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Aucun]);
    let t = b.echeance().unwrap();
    b.minuteur(t);
    assert_eq!(sortis(&mut b, t).iter().map(|x| x.1).collect::<Vec<_>>(), [Compte::Renvoi]);
}

/// Ce que chaque chemin compte, selon la route et la mémoire.
#[test]
fn chemins_d_un_segment() {
    fn compte(c: Compte, route: bool, paquet: bool) -> [u64; 5] {
        let m = Box::leak(Box::new(Mib::new()));
        c.compter(m, route, paquet);
        [m.valeur_tcp(Tcp::OutSegs), m.valeur_tcp(Tcp::RetransSegs), m.valeur_tcp(Tcp::OutRsts), m.valeur_ip(Ip::OutNoRoutes),
            m.valeur_ip(Ip::OutDiscards)]
    }
    assert_eq!(compte(Compte::Neuf, true, true), [1, 0, 0, 0, 0]);
    assert_eq!(compte(Compte::Neuf, false, true), [1, 0, 0, 1, 0]);
    assert_eq!(compte(Compte::Neuf, true, false), [0; 5]);
    assert_eq!(compte(Compte::Renvoi, true, false), [0, 1, 0, 0, 0]);
    // Sans route, un renvoi n'est rien (`rebuild_header` échoue avant RetransSegs).
    assert_eq!(compte(Compte::Renvoi, false, true), [0; 5]);
    assert_eq!(compte(Compte::Aucun, true, true), [0; 5]);
    assert_eq!(compte(Compte::Coupure, true, true), [1, 0, 1, 0, 0]);
    assert_eq!(compte(Compte::Coupure, true, false), [0, 0, 1, 0, 0]);
    assert_eq!(compte(Compte::SynAck { renvoi: true }, true, true), [1, 1, 0, 0, 0]);
    assert_eq!(compte(Compte::SynAck { renvoi: false }, false, true), [0, 0, 0, 1, 0]);
    assert_eq!(compte(Compte::Reponse { rst: true }, true, true), [1, 0, 1, 0, 0]);
    assert_eq!(compte(Compte::Reponse { rst: false }, true, false), [1, 0, 0, 0, 1]);
    assert_eq!(compte(Compte::Reponse { rst: true }, false, false), [1, 0, 1, 0, 0]);
}
