//! Les pertes de la connexion (`sk_drops`) : chaque segment que Linux jette par
//! `tcp_drop_reason` (net/ipv4/tcp_input.c, 6.18), ou par le `discard_and_relse` de
//! `tcp_v4_rcv` quand `tcp_check_req` refuse le segment d'une fille, en est une ; un
//! segment qui reçoit un RST, ou qui coupe la connexion, n'en est pas une.

use super::essais::*;
use super::*;

fn ack_pur(c: &C) -> Tcp {
    Tcp { seq: c.rcv_nxt, ack: c.snd_una, drapeaux: tcp::ACK, fenetre: 65535, ..Tcp::default() }
}

/// Reçoit `t` (et `n` octets), et rend les pertes qu'il a faites.
fn pertes(c: &mut C, t: &Tcp, n: usize) -> u32 {
    c.recevoir(t, octets(n, n), HEURE);
    c.prendre_pertes()
}

/// `tcp_validate_incoming` : hors de la fenêtre, déjà reçu, un RST ou un SYN dans la
/// fenêtre ; puis un ACK que `tcp_ack` rejette (de ce qui n'est pas encore parti).
#[test]
fn ce_que_la_validation_refuse() {
    let mut c = etablie(true);
    let t = ack_pur(&c);
    // Un ACK ordinaire, des données dans l'ordre : rien.
    assert_eq!(pertes(&mut c, &t, 0), 0);
    let t = ack_pur(&c);
    assert_eq!(pertes(&mut c, &t, 100), 0);
    // Au-delà de la fenêtre : jeté, avec un ACK.
    let loin = Tcp { seq: c.rcv_nxt.wrapping_add(1 << 20), ..ack_pur(&c) };
    let e = c.recevoir(&loin, octets(100, 100), HEURE);
    assert!(e.a_emettre);
    assert_eq!(c.prendre_pertes(), 1);
    // Déjà reçu (avant RCV.WUP comme après) : jeté.
    let vieux = Tcp { seq: c.rcv_nxt - 100, ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &vieux, 100), 1);
    // Un RST dans la fenêtre, pas au bord : l'ACK de défi, et une perte ; au bord : la
    // connexion coupée, sans perte.
    let rst = Tcp { seq: c.rcv_nxt + 10, drapeaux: tcp::RST, ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &rst, 0), 1);
    assert_eq!(c.etat(), Etat::Etablie);
    // Un RST hors de la fenêtre : jeté.
    let rst_loin = Tcp { seq: c.rcv_nxt.wrapping_add(1 << 20), ..rst };
    assert_eq!(pertes(&mut c, &rst_loin, 0), 1);
    // Un SYN : l'ACK de défi, une perte.
    let syn = Tcp { drapeaux: tcp::SYN | tcp::ACK, ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &syn, 0), 1);
    // L'ACK de ce que nous n'avons pas envoyé : rejeté.
    let avenir = Tcp { ack: c.snd_nxt + 1000, ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &avenir, 0), 1);
    let rst = Tcp { seq: c.rcv_nxt, drapeaux: tcp::RST, ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &rst, 0), 0);
    assert_eq!(c.etat(), Etat::Fermee);
}

/// Ni ACK, ni RST, ni SYN : jeté avant même le numéro de séquence (TCP_FLAGS), sans
/// ACK, même hors de la fenêtre.
#[test]
fn sans_drapeaux() {
    let mut c = etablie(true);
    let loin = Tcp { seq: c.rcv_nxt.wrapping_add(1 << 20), drapeaux: 0, ..ack_pur(&c) };
    let e = c.recevoir(&loin, octets(100, 100), HEURE);
    assert!(!e.a_emettre);
    assert!(!c.ack_maintenant);
    assert_eq!(c.prendre_pertes(), 1);
    // Un FIN seul, dans la fenêtre : jeté aussi.
    let fin_seul = Tcp { drapeaux: tcp::FIN, ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &fin_seul, 0), 1);
    assert_eq!(c.etat(), Etat::Etablie);
}

/// PAWS (`tcp_validate_incoming`) : un vieil ACK désordonné est jeté sans réponse,
/// un autre segment refusé reçoit son ACK ; les deux sont des pertes.
#[test]
fn paws() {
    let mut c = etablie(true);
    c.rto = 1_000_000_000;
    c.ts = Some(Horodatages { recent: 5000, instant: HEURE, decalage: 0 });
    let ts = |val: u32| tcp::Options { horodatage: Some((val, 0)), ..tcp::Options::default() };
    let refuse = Tcp { options: ts(1000), ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &refuse, 100), 1);
    let vieil_ack = Tcp { seq: c.rcv_nxt - 1, options: ts(1000), ..ack_pur(&c) };
    assert_eq!(c.ack_desordonne(&vieil_ack, 1000, vieil_ack.seq), Desordonne::VieilAck);
    assert_eq!(pertes(&mut c, &vieil_ack, 0), 1);
}

/// `tcp_data_queue` : une fenêtre fermée, des données qui ne trouvent pas de mémoire.
#[test]
fn fenetre_fermee() {
    let mut c = etablie(true);
    c.rcv_wup = c.rcv_nxt;
    c.rcv_wnd = 0;
    // (La file vide : `tcp_sequence` laisse passer ce qui déborde.)
    let t = ack_pur(&c);
    assert_eq!(pertes(&mut c, &t, 100), 1);
    // Un FIN seul passe (« bare FIN packets in a loop »).
    let fin_seul = Tcp { drapeaux: tcp::FIN | tcp::ACK, ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &fin_seul, 0), 0);
    assert_eq!(c.etat(), Etat::AttenteFermeture);
}

/// Après le FIN de l'autre (CLOSE_WAIT, CLOSING, LAST_ACK), ce qui n'est pas en
/// arrière n'est pas pris : une perte, un ACK pur aussi (`tcp_rcv_state_process`).
#[test]
fn apres_le_fin_de_l_autre() {
    let mut c = etablie(true);
    let fin_ = Tcp { drapeaux: tcp::FIN | tcp::ACK, ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &fin_, 0), 0);
    assert_eq!(c.etat(), Etat::AttenteFermeture);
    let t = ack_pur(&c);
    assert_eq!(pertes(&mut c, &t, 0), 1);
    en_vol(&mut c, 1);
    let t = Tcp { ack: fin(0), ..ack_pur(&c) };
    assert_eq!(pertes(&mut c, &t, 0), 1);
    assert_eq!(c.snd_una, fin(0));
    // Le FIN répété (en arrière) : des données déjà reçues (TCP_OLD_DATA).
    let encore = Tcp { seq: c.rcv_nxt - 1, ..fin_ };
    assert_eq!(pertes(&mut c, &encore, 0), 1);
    // En ESTABLISHED, un ACK pur n'est pas une perte.
    let mut d = etablie(true);
    let t = ack_pur(&d);
    assert_eq!(pertes(&mut d, &t, 0), 0);
}

/// SYN_SENT : un RST sans ACK, un segment sans SYN (`discard_and_undo`) ; pas un
/// RST qui refuse notre SYN, ni un ACK faux, qui reçoit un RST.
#[test]
fn en_syn_sent() {
    let base = |c: &C| Tcp { seq: 5000, ack: c.snd_nxt, drapeaux: tcp::ACK, fenetre: 65535, ..Tcp::default() };
    let mut c = syn_envoye();
    let rst = Tcp { drapeaux: tcp::RST, ..base(&c) };
    assert_eq!(pertes(&mut c, &rst, 0), 1);
    let t = base(&c);
    assert_eq!(pertes(&mut c, &t, 0), 1);
    let sans = Tcp { drapeaux: 0, ..base(&c) };
    assert_eq!(pertes(&mut c, &sans, 0), 1);
    let faux = Tcp { ack: c.snd_nxt + 100, ..base(&c) };
    assert_eq!(pertes(&mut c, &faux, 0), 0);
    assert_eq!(c.etat(), Etat::SynEnvoye);
    let refus = Tcp { drapeaux: tcp::RST | tcp::ACK, ..base(&c) };
    assert_eq!(pertes(&mut c, &refus, 0), 0);
    assert_eq!(c.etat(), Etat::Fermee);
}

/// Une fille en SYN_RECEIVED (`tcp_check_req`) : chaque refus est une perte (de
/// l'écoute, pour le noyau), sauf l'ACK qui n'acquitte pas notre SYN, rendu à l'écoute.
#[test]
fn une_fille() {
    let pour = |c: &C, drapeaux: u8| Tcp { seq: c.rcv_nxt, ack: ISS + 1, drapeaux, fenetre: 65535, ..Tcp::default() };
    let mut c = fille(false);
    // Le SYN répété : notre SYN-ACK repart ; une perte.
    let syn = Tcp { seq: c.irs, drapeaux: tcp::SYN, ..pour(&c, 0) };
    assert_eq!(pertes(&mut c, &syn, 0), 1);
    // Sans ACK ; hors de la fenêtre ; un ACK faux (pas une perte).
    let t = pour(&c, 0);
    assert_eq!(pertes(&mut c, &t, 0), 1);
    let loin = Tcp { seq: c.rcv_nxt.wrapping_add(1 << 20), ..pour(&c, tcp::ACK) };
    assert_eq!(pertes(&mut c, &loin, 0), 1);
    let faux = Tcp { ack: ISS + 7, ..pour(&c, tcp::ACK) };
    assert_eq!(pertes(&mut c, &faux, 0), 0);
    assert_eq!(c.etat(), Etat::SynRecu);
    // TCP_DEFER_ACCEPT : l'ACK nu est jeté.
    c.reglages.defer_accept = 1;
    let t = pour(&c, tcp::ACK);
    assert_eq!(pertes(&mut c, &t, 0), 1);
    c.reglages.defer_accept = 0;
    // Le bon ACK : elle naît, sans perte.
    let t = pour(&c, tcp::ACK);
    assert_eq!(pertes(&mut c, &t, 0), 0);
    assert_eq!(c.etat(), Etat::Etablie);
    // Un RST dans la fenêtre défait une autre fille : une perte.
    let mut d = fille(false);
    let t = pour(&d, tcp::RST);
    assert_eq!(pertes(&mut d, &t, 0), 1);
    assert_eq!(d.etat(), Etat::Fermee);
}

/// La file hors d'ordre (`tcp_data_queue_ofo`, `tcp_ofo_queue`) : une charge toute
/// contenue dans une autre, celles qu'une plus grande recouvre, celle qu'une plus longue
/// remplace au même numéro, celles qui arrivent déjà reçues quand le trou se comble.
#[test]
fn hors_d_ordre() {
    let mut c = etablie(true);
    let b = c.rcv_nxt;
    let base = ack_pur(&c);
    let a = |seq: u32| Tcp { seq, ..base };
    assert_eq!(pertes(&mut c, &a(b + 1000), 500), 0);
    // Toute contenue : elle est jetée.
    assert_eq!(pertes(&mut c, &a(b + 1000), 500), 1);
    assert_eq!(pertes(&mut c, &a(b + 1100), 100), 1);
    // Au même numéro, plus longue : elle remplace l'autre, jetée.
    assert_eq!(pertes(&mut c, &a(b + 1000), 1000), 1);
    // Elle en couvre une en entier : jetée.
    assert_eq!(pertes(&mut c, &a(b + 500), 2000), 1);
    assert_eq!(pertes(&mut c, &a(b + 2600), 100), 0);
    // Le trou comblé par un segment qui va plus loin que la première : elle arrive déjà
    // reçue (TCP_OFO_DROP) ; la suivante a encore du neuf.
    assert_eq!(pertes(&mut c, &a(b), 2600), 1);
    assert_eq!(c.rcv_nxt, b + 2700);
    assert!(c.hors_ordre.vide());
}
