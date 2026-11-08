//! Le texte reçu et les ACK retardés (`tcp_data_queue`, `tcp_event_data_recv`, `__tcp_ack_snd_check`,
//! `tcp_send_delayed_ack`, `tcp_comp_sack_*`). Le simulateur et `tests/tcp.rs` les font tourner sans
//! regarder les durées ; ici, chacune est calculée à la main d'après les formules de Linux.

use super::essais::*;
use super::*;

/// Un segment de texte de l'autre.
fn texte(c: &C, seq: u32) -> Tcp {
    Tcp { seq, ack: c.snd_una, drapeaux: tcp::ACK, fenetre: 65535, ..Tcp::default() }
}

/// Une connexion dont la fenêtre annoncée est juste celle qu'on lui donne.
fn fenetre(wnd: u32) -> C {
    let mut c = etablie(true);
    c.rcv_wup = c.rcv_nxt;
    c.rcv_wnd = wnd;
    c.ack.programme = false;
    c.ack_maintenant = false;
    c
}

/// Une fenêtre fermée : pas de texte dans l'ordre, sauf un FIN seul (« Some stacks are known to send
/// bare FIN packets in a loop even if we send RWIN 0 »).
#[test]
fn le_texte_et_la_fenetre_fermee() {
    let appel = |c: &mut C, n: usize, fin: bool| {
        let seq = c.rcv_nxt;
        let t = texte(c, seq);
        let mut e = Effets::default();
        c.recevoir_texte(&t, seq, octets(n, 600 + n), fin, HEURE, &mut e);
    };
    let mut c = fenetre(0);
    let nxt = c.rcv_nxt;
    appel(&mut c, 5, true);
    assert_eq!(c.rcv_nxt, nxt, "le texte et le FIN : rien");
    assert!(c.ack_maintenant);
    assert!(!c.fin_recue);
    let mut c = fenetre(0);
    let nxt = c.rcv_nxt;
    appel(&mut c, 5, false);
    assert_eq!(c.rcv_nxt, nxt);
    let mut c = fenetre(0);
    let nxt = c.rcv_nxt;
    appel(&mut c, 0, true);
    assert_eq!(c.rcv_nxt, nxt + 1, "un FIN seul passe");
    assert!(c.fin_recue);
}

/// Le début déjà reçu : la suite entre, sauf fenêtre fermée.
#[test]
fn le_texte_a_cheval() {
    let appel = |c: &mut C| {
        let seq = c.rcv_nxt - 3;
        let t = texte(c, seq);
        let mut e = Effets::default();
        c.recevoir_texte(&t, seq, octets(8, 608), false, HEURE, &mut e);
    };
    let mut c = fenetre(1000);
    let nxt = c.rcv_nxt;
    appel(&mut c);
    assert_eq!(c.rcv_nxt, nxt + 5);
    assert_eq!(c.dsack, Some((nxt - 3, nxt)));
    assert!(!c.ack_maintenant, "de la place : pas un hors-fenêtre");
    let mut c = fenetre(0);
    let nxt = c.rcv_nxt;
    appel(&mut c);
    assert_eq!(c.rcv_nxt, nxt);
    assert_eq!(c.dsack, Some((nxt - 3, nxt)));
    assert!(c.ack_maintenant);
}

/// Pas de place pour le segment : gardé seulement s'il n'y a rien à lire, ou s'il ne porte rien ; un
/// FIN seul doit toujours pouvoir passer, sinon la connexion resterait ouverte.
#[test]
fn le_texte_sans_memoire() {
    // La mémoire refusée, et rien à élaguer : tout segment est de trop.
    let pleine = || {
        let mut c = etablie(true);
        let t = texte(&c, c.rcv_nxt);
        let mut e = Effets::default();
        let seq = c.rcv_nxt;
        c.recevoir_texte(&t, seq, octets(5, 605), false, HEURE, &mut e);
        assert_eq!(c.octets_reception, 5);
        c.rcvbuf = 1;
        c.memoire = Memoire::Limite;
        c.rcv_wup = c.rcv_nxt;
        c.rcv_wnd = 1000;
        c
    };
    // Du texte : jeté, et une fenêtre nulle tout de suite.
    let mut c = pleine();
    let seq = c.rcv_nxt;
    let t = texte(&c, seq);
    let mut e = Effets::default();
    c.recevoir_texte(&t, seq, octets(5, 605), false, HEURE, &mut e);
    assert_eq!(c.rcv_nxt, seq, "jeté");
    assert!(c.ack.sans_memoire && c.ack.urgent && c.ack.programme && e.lisible);
    // Un FIN seul : gardé.
    let mut c = pleine();
    let seq = c.rcv_nxt;
    let t = texte(&c, seq);
    let mut e = Effets::default();
    c.recevoir_texte(&t, seq, octets(0, 0), true, HEURE, &mut e);
    assert!(c.ack.sans_memoire);
    assert_eq!(c.rcv_nxt, seq + 1);
    assert!(c.fin_recue);
}

/// `tcp_event_data_recv` : l'`ato` suit l'écart entre les arrivées.
#[test]
fn l_ato_suit_les_arrivees() {
    let essai = |ato: u64, m: u64, rto: u64| {
        let mut c = etablie(true);
        c.rto = rto;
        c.ack.ato = ato;
        c.ack.rapides = 0;
        c.ack.lrcvtime = HEURE;
        c.ack.rcv_mss = 1000;
        let t = texte(&c, c.rcv_nxt);
        c.donnees_recues(&t, 10, 600, HEURE + m);
        assert_eq!(c.ack.lrcvtime, HEURE + m);
        (c.ack.ato, c.ack.rapides)
    };
    let (s, cent) = (1_000 * MS, 100 * MS);
    // Tout juste la moitié du minimum, ou moins : (ato/2) + min/2.
    assert_eq!(essai(cent, ATO_MIN / 2, s).0, cent / 2 + ATO_MIN / 2);
    assert_eq!(essai(cent, 1, s).0, cent / 2 + ATO_MIN / 2);
    // Au-delà, et sous l'ato : (ato/2) + m, au plus le RTO.
    let m = ATO_MIN / 2 + 1;
    assert_eq!(essai(cent, m, s).0, cent / 2 + m);
    assert_eq!(essai(cent, 99 * MS, 110 * MS).0, 110 * MS);
    // Tout juste l'ato : rien ne change.
    assert_eq!(essai(cent, cent, s).0, cent);
    assert_eq!(essai(cent, cent + 1, s), (cent, 0), "plus long, sous le RTO : rien");
    // Tout juste le RTO : rien ; au-delà, l'émetteur repart en démarrage lent : des ACK rapides.
    assert_eq!(essai(cent, s, s).1, 0);
    assert!(essai(cent, s + 1, s).1 > 0);
    // Les premières données.
    let (ato, rapides) = essai(0, 5, s);
    assert_eq!(ato, ATO_MIN);
    assert!(rapides > 0);
}

/// `tcp_incr_quickack` : la moitié de la fenêtre, au moins 2, au plus 16.
#[test]
fn les_ack_rapides() {
    let essai = |wnd: u32, mss: u32, avant: u32| {
        let mut c = etablie(true);
        c.rcv_wnd = wnd;
        c.ack.rcv_mss = mss;
        c.ack.rapides = avant;
        c.ajouter_ack_rapides();
        c.ack.rapides
    };
    assert_eq!(essai(8000, 1000, 0), 4);
    assert_eq!(essai(1000, 1000, 0), 2, "rien : 2");
    assert_eq!(essai(1 << 20, 1000, 0), ACK_RAPIDES_MAX);
    assert_eq!(essai(8000, 1000, 9), 9, "jamais moins qu'avant");
    assert_eq!(essai(8000, 0, 0), ACK_RAPIDES_MAX.min(4000), "pas de division par zéro");
}

/// `__tcp_ack_snd_check` : plus d'un segment plein, et assez à lire pour SO_RCVLOWAT.
#[test]
fn l_ack_quand_il_manque_de_quoi_lire() {
    let prete = |a_lire: u32, lowat: u32| {
        let mut c = etablie(true);
        c.ack.programme = true;
        c.ack.rapides = 0;
        c.ack.rcv_mss = 1000;
        c.rcv_wup = c.rcv_nxt.wrapping_sub(2000);
        c.rcv_lu = c.rcv_nxt.wrapping_sub(a_lire);
        c.rcvlowat = lowat;
        // La fenêtre qu'on annoncerait reculerait : ce test-là ne le décide pas.
        c.rcv_wnd = 1 << 30;
        assert!(c.choisir_fenetre() < c.rcv_wnd);
        c
    };
    let mut c = prete(99, 100);
    c.verifier_ack(HEURE);
    assert!(c.ack_maintenant, "pas assez à lire : l'autre doit continuer");
    let mut c = prete(100, 100);
    c.verifier_ack(HEURE);
    assert!(!c.ack_maintenant, "juste assez");
    let mut c = prete(101, 100);
    c.verifier_ack(HEURE);
    assert!(!c.ack_maintenant);
}

/// `tcp_comp_sack_*` : trois ACK dupliqués par RCV.NXT, puis un seul, après 5 % du RTT, au plus 1 ms.
#[test]
fn les_ack_comprimes() {
    let prete = |srtt: u64, rcv_rtt8: u64| {
        let mut c = etablie(true);
        c.ack.programme = true;
        c.ack.rapides = 0;
        c.ack.rcv_mss = 1000;
        c.rcv_wup = c.rcv_nxt;
        c.hors_ordre.ranger(c.rcv_nxt + 100, octets(1, 600)).ok();
        c.comprime_rcv_nxt = c.rcv_nxt;
        c.ack_dupliques = TCP_REORDERING;
        if srtt != 0 {
            c.rtt.echantillon(srtt, c.snd_una, c.snd_nxt);
        }
        c.rcv_rtt8 = rcv_rtt8;
        c
    };
    // Trop de doublons pour ce RCV.NXT : comprimé.
    let mut c = prete(8 * MS, 1 << 40);
    c.verifier_ack(HEURE);
    assert!(!c.ack_maintenant);
    assert_eq!(c.ack_comprimes, 1);
    // 8 ms : 8/20 de ms, par l'estimation de l'émetteur, plus petite.
    assert_eq!(c.t_comprime, Some(HEURE + 8 * MS / 20));
    // Le RTT du récepteur, s'il est plus petit, ou sans estimation.
    let mut c = prete(8 * MS, 8 * 4 * MS);
    c.verifier_ack(HEURE);
    assert_eq!(c.t_comprime, Some(HEURE + 4 * MS / 20));
    let mut c = prete(0, 8 * 4 * MS);
    c.verifier_ack(HEURE);
    assert_eq!(c.t_comprime, Some(HEURE + 4 * MS / 20));
    // Tout juste égal : c'est le même.
    let mut c = prete(8 * MS, 8 * 8 * MS);
    c.verifier_ack(HEURE);
    assert_eq!(c.t_comprime, Some(HEURE + 8 * MS / 20));
    // Au plus 1 ms.
    let mut c = prete(100 * MS, 1 << 40);
    c.verifier_ack(HEURE);
    assert_eq!(c.t_comprime, Some(HEURE + COMP_SACK_DELAI));
    // Déjà armé : on ne le repousse pas.
    let mut c = prete(8 * MS, 1 << 40);
    c.t_comprime = Some(HEURE + 1);
    c.verifier_ack(HEURE + 5);
    assert_eq!(c.t_comprime, Some(HEURE + 1));
    // Un autre RCV.NXT : le compte repart, et l'ACK part.
    let mut c = prete(8 * MS, 1 << 40);
    c.comprime_rcv_nxt = c.rcv_nxt - 1;
    c.verifier_ack(HEURE);
    assert!(c.ack_maintenant);
    assert_eq!((c.ack_dupliques, c.comprime_rcv_nxt), (1, c.rcv_nxt));
    assert_eq!(c.ack_comprimes, 0);
}

/// `tcp_send_delayed_ack` : au-dessus du minimum, le délai est borné par le RTT mesuré ; et toujours
/// par 200 ms.
#[test]
fn l_ack_retarde() {
    let essai = |ato: u64, srtt: u64| {
        let mut c = etablie(true);
        c.ack.ato = ato;
        if srtt != 0 {
            c.rtt.echantillon(srtt, c.snd_una, c.snd_nxt);
        }
        c.retarder_ack(HEURE);
        c.ack.t.unwrap() - HEURE
    };
    assert_eq!(essai(100 * MS, 50 * MS), 50 * MS, "le RTT borne");
    assert_eq!(essai(100 * MS, 0), 100 * MS, "pas de RTT");
    assert_eq!(essai(300 * MS, 0), DELACK_MAX);
    // Le minimum, jamais moins, même si le RTT est plus court.
    assert_eq!(essai(100 * MS, MS), ATO_MIN);
    assert_eq!(essai(ATO_MIN, MS), ATO_MIN);
    // Une échéance plus proche reste ; presque échue, l'ACK part tout de suite.
    let mut c = etablie(true);
    c.ack.ato = 100 * MS;
    c.ack.t = Some(HEURE + 30 * MS);
    c.retarder_ack(HEURE);
    assert_eq!(c.ack.t, Some(HEURE + 30 * MS));
    assert!(!c.ack_maintenant);
    let mut c = etablie(true);
    c.ack.ato = 100 * MS;
    c.ack.t = Some(HEURE + 25 * MS);
    c.retarder_ack(HEURE);
    assert!(c.ack_maintenant);
}
