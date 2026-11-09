//! Ce qui part (`tcp_write_xmit`, `__tcp_transmit_skb`, les SYN, la sonde de fenêtre) et quand on
//! renonce (`tcp_write_timeout`, `tcp_probe_timer`) : posés juste à la borne ; les segments se lisent
//! tels qu'ils sortent, les délais en ns, d'après les formules de Linux.

use super::essais::*;
use super::*;
use alloc::vec::Vec;

/// Ce qu'émet la connexion, à `t`.
fn sortants(c: &mut C, t: u64) -> Vec<Tcp> {
    let mut v = Vec::new();
    c.emettre(t, |s| v.push(s.entete));
    v
}

/// `n` octets écrits, pas encore envoyés.
fn ecrits(c: &mut C, n: usize) {
    let r = c.ecrire::<()>(n, |d| {
        d.fill(1);
        Ok(())
    });
    assert_eq!(r, Ok(n));
}

/// `reqsk_timer_handler` : un SYN-ACK de plus, le recul compté.
#[test]
fn le_minuteur_d_une_fille() {
    let mut c = fille(false);
    c.rto = 1000 * MS;
    let (r, t) = (c.total_retrans, c.total_rto);
    let mut e = Effets::default();
    c.minuteur_fille(HEURE, &mut e);
    assert!(e.a_emettre && c.syn_du);
    assert_eq!((c.recul, c.retransmissions), (1, 1));
    assert_eq!((c.total_retrans, c.total_rto), (r + 1, t + 1));
    assert_eq!(c.rto, 2000 * MS);
    assert_eq!(c.t_xmit, Some(HEURE + 2000 * MS));
}

/// `tcp_write_timeout` : le compte de la poignée de main.
#[test]
fn abandonner_la_poignee_de_main() {
    // Le temps modélisé ne décide pas ici : l'heure est celle de la dernière retransmission.
    let essai = |mut c: C, n: u32| {
        c.retransmissions = n;
        c.retrans_stamp = HEURE;
        c.temps_ecoule(HEURE)
    };
    assert!(essai(fille(false), SYNACK_ESSAIS), "le SYN-ACK : 5");
    assert!(!essai(fille(false), SYNACK_ESSAIS - 1));
    // Le SYN : 6, plus les quatre linéaires.
    assert!(essai(syn_envoye(), SYN_ESSAIS + SYN_LINEAIRES));
    assert!(!essai(syn_envoye(), SYN_ESSAIS + SYN_LINEAIRES - 1));
}

/// `tcp_orphan_retries` : 8 tant qu'elle semble vivante, c'est-à-dire sous RTO_MAX ; aucune ensuite.
#[test]
fn abandonner_une_orpheline() {
    let essai = |rto: u64, t: u64| {
        let mut c = etablie(true);
        c.reglages.orpheline = true;
        c.retransmissions = 1;
        c.retrans_stamp = HEURE;
        c.rto = rto;
        c.temps_ecoule(HEURE + t)
    };
    let zero = temps_modele(0, RTO_MIN);
    let huit = temps_modele(ORPHELINE_ESSAIS, RTO_MIN);
    assert!(essai(RTO_MAX, zero));
    assert!(!essai(RTO_MAX, zero - 1));
    assert!(!essai(RTO_MAX - 1, zero));
    assert!(essai(RTO_MAX - 1, huit));
    assert!(!essai(RTO_MAX - 1, huit - 1));
}

/// `tcp_rtx_probe0_timed_out`.
#[test]
fn la_fenetre_nulle_trop_longtemps() {
    let mut c = etablie(true);
    c.dernier_recu = HEURE;
    let l = 2 * RTO_MAX;
    assert!(c.fenetre_nulle_echue(HEURE + l + 1, l + 1));
    assert!(!c.fenetre_nulle_echue(HEURE + l, l + 1), "le silence : tout juste");
    assert!(!c.fenetre_nulle_echue(HEURE + l + 1, l), "depuis : tout juste");
    // TCP_USER_TIMEOUT : dépassé, c'est fini ; et il baisse la limite.
    let u = 5000 * MS;
    c.reglages.delai_utilisateur = u;
    assert!(c.fenetre_nulle_echue(HEURE, u + 1));
    assert!(!c.fenetre_nulle_echue(HEURE, u));
    c.reglages.delai_utilisateur = l + 100;
    assert!(c.fenetre_nulle_echue(HEURE + l + 1, l + 1), "plus grand : la limite reste");
}

/// Ce qui attend, en numéros de séquence : le FIN compte s'il part avec le dernier morceau.
#[test]
fn le_prochain_segment() {
    let mut c = etablie(true);
    assert_eq!(c.prochain_segment(), None);
    ecrits(&mut c, 10);
    assert_eq!(c.prochain_segment(), Some(10));
    c.fin_voulue = true;
    assert_eq!(c.prochain_segment(), Some(11));
    // Un MSS, et pas encore le FIN.
    let mut c = etablie(true);
    ecrits(&mut c, 2 * MSS as usize);
    c.fin_voulue = true;
    assert_eq!(c.prochain_segment(), Some(MSS));
    // Le FIN seul.
    let mut c = etablie(true);
    c.fin_voulue = true;
    assert_eq!(c.prochain_segment(), Some(1));
    // Le FIN déjà parti : plus rien.
    c.snd_nxt += 1;
    assert_eq!(c.prochain_segment(), None);
}

/// `tcp_ack_probe` : la fenêtre laisse passer le prochain segment : plus de sonde, et sinon la suivante.
#[test]
fn l_ack_d_une_sonde() {
    let prete = |fenetre: u32, sorte: Minuteur| {
        let mut c = etablie(true);
        ecrits(&mut c, 10);
        c.recul = 2;
        c.sondes_debut = Some(HEURE);
        c.t_sorte = sorte;
        c.t_xmit = Some(HEURE + 1);
        c.snd_wnd = fenetre;
        c.rto = 1000 * MS;
        c
    };
    let mut c = prete(10, Minuteur::Sonde);
    c.ack_de_sonde(HEURE);
    assert_eq!((c.recul, c.sondes_debut, c.t_xmit), (0, None, None));
    // Un autre minuteur reste.
    let mut c = prete(10, Minuteur::Retransmission);
    c.ack_de_sonde(HEURE);
    assert_eq!((c.recul, c.t_xmit), (0, Some(HEURE + 1)));
    // Encore fermée : le RTO, doublé par le recul.
    let mut c = prete(9, Minuteur::Sonde);
    c.ack_de_sonde(HEURE);
    assert_eq!(c.recul, 2);
    assert_eq!(c.t_xmit, Some(HEURE + 4000 * MS));
    assert_eq!(c.t_sorte, Minuteur::Sonde);
    // Rien à envoyer : rien.
    let mut c = etablie(true);
    c.t_xmit = Some(HEURE + 1);
    c.recul = 2;
    c.ack_de_sonde(HEURE);
    assert_eq!((c.recul, c.t_xmit), (2, Some(HEURE + 1)));
}

/// `tcp_clamp_probe0_to_user_timeout`.
#[test]
fn le_delai_d_une_sonde() {
    let d = 2000 * MS;
    let u = 1000 * MS;
    let mut c = etablie(true);
    c.reglages.delai_utilisateur = u;
    assert_eq!(c.borne_sonde(HEURE, d), d, "pas encore commencé");
    c.sondes_debut = Some(HEURE);
    c.reglages.delai_utilisateur = 0;
    assert_eq!(c.borne_sonde(HEURE + 300 * MS, d), d);
    c.reglages.delai_utilisateur = u;
    assert_eq!(c.borne_sonde(HEURE + 300 * MS, d), 700 * MS);
    assert_eq!(c.borne_sonde(HEURE + 300 * MS, 100 * MS), 100 * MS);
    // Au moins deux tics.
    assert_eq!(c.borne_sonde(HEURE + u - 1, d), 2 * sack::JIFFY);
    // Passé : `minuteur_sonde` abandonnera.
    assert_eq!(c.borne_sonde(HEURE + u, d), d);
    assert_eq!(c.borne_sonde(HEURE + u + 1, d), d);
}

/// `tcp_probe_timer` : ce qui l'arrête.
#[test]
fn le_minuteur_de_sonde() {
    let lancer = |c: &mut C, t: u64| {
        let mut e = Effets::default();
        c.minuteur_sonde(t, &mut e);
        e
    };
    // Des données : la sonde part, le recul et le compte montent.
    let prete = || {
        let mut c = etablie(true);
        ecrits(&mut c, 10);
        c.sondes = 2;
        c.sondes_debut = Some(HEURE);
        c.rto = 1000 * MS;
        c
    };
    let mut c = prete();
    assert!(lancer(&mut c, HEURE).a_emettre);
    assert!(c.sonde_due);
    assert_eq!((c.sondes, c.recul), (3, 1));
    // Quelque chose en vol, rien à envoyer, ou plus synchronisée : plus de sonde.
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    ecrits(&mut c, 10);
    c.sondes = 2;
    c.sondes_debut = Some(HEURE);
    assert_eq!(lancer(&mut c, HEURE), Effets::default());
    assert_eq!((c.sondes, c.sondes_debut, c.sonde_due), (0, None, false));
    let mut c = etablie(true);
    c.sondes = 2;
    c.sondes_debut = Some(HEURE);
    lancer(&mut c, HEURE);
    assert_eq!((c.sondes, c.sondes_debut, c.sonde_due), (0, None, false));
    let mut c = prete();
    c.etat = Etat::SynEnvoye;
    lancer(&mut c, HEURE);
    assert_eq!((c.sondes, c.sondes_debut, c.sonde_due), (0, None, false));
    // TCP_USER_TIMEOUT : tout juste passé.
    let u = 1000 * MS;
    let mut c = prete();
    c.reglages.delai_utilisateur = u;
    lancer(&mut c, HEURE + u);
    assert_eq!((c.etat(), c.erreur), (Etat::Fermee, ETIMEDOUT));
    let mut c = prete();
    c.reglages.delai_utilisateur = u;
    lancer(&mut c, HEURE + u - 1);
    assert_eq!(c.etat(), Etat::Etablie);
    // Le recul s'arrête à `tcp_retries2`.
    let mut c = prete();
    c.recul = RETRIES2;
    c.rto = MS;
    lancer(&mut c, HEURE);
    assert_eq!(c.recul, RETRIES2);
    let mut c = prete();
    c.recul = RETRIES2 - 1;
    c.rto = MS;
    lancer(&mut c, HEURE);
    assert_eq!(c.recul, RETRIES2);
}

/// `tcp_probe_timer`, une orpheline : 8 sondes tant qu'elle est vivante ; passé RTO_MAX, aucune.
#[test]
fn le_minuteur_de_sonde_d_une_orpheline() {
    let prete = |rto: u64, recul: u32, sondes: u32| {
        let mut c = etablie(true);
        ecrits(&mut c, 10);
        c.reglages.orpheline = true;
        c.sondes_debut = Some(HEURE);
        c.rto = rto;
        c.recul = recul;
        c.sondes = sondes;
        let mut e = Effets::default();
        c.minuteur_sonde(HEURE, &mut e);
        c.etat()
    };
    assert_eq!(prete(1000 * MS, 0, ORPHELINE_ESSAIS - 1), Etat::Etablie);
    assert_eq!(prete(1000 * MS, 0, ORPHELINE_ESSAIS), Etat::Fermee);
    assert_eq!(prete(RTO_MAX, 0, 0), Etat::Fermee, "le recul au plafond");
    assert_eq!(prete(RTO_MAX - 1, 0, 0), Etat::Etablie);
    // Le recul au-delà de 8, encore vivante : elle continue.
    assert_eq!(prete(MS, ORPHELINE_ESSAIS, 0), Etat::Etablie);
}

/// L'en-tête : l'ACK seulement avec son drapeau ; le pointeur urgent trop loin pour 16 bits.
#[test]
fn l_en_tete() {
    let mut c = etablie(true);
    assert_eq!(c.entete_avec(1, tcp::SYN, 0).ack, 0);
    assert_eq!(c.entete_avec(1, tcp::ACK, 0).ack, c.rcv_nxt);
    let seq = c.snd_una;
    c.snd_nxt = seq;
    c.snd_up = seq.wrapping_add(0x10005);
    let h = c.entete_avec(seq, tcp::ACK, 0);
    assert_eq!(h.urgent, 0xFFFF);
    assert_eq!(h.drapeaux, tcp::ACK | tcp::URG);
    // À portée : la distance.
    c.snd_up = seq.wrapping_add(0x10);
    let h = c.entete_avec(seq, tcp::ACK, 0);
    assert_eq!(h.urgent, 0x10);
    assert_eq!(h.drapeaux, tcp::ACK | tcp::URG);
}

/// `tcp_event_data_sent` : rien en vol, CUBIC décale son époque du temps de silence ; répondre vite,
/// c'est une conversation (le ping-pong).
#[test]
fn un_segment_de_donnees_part() {
    let prete = || {
        let mut c = etablie(true);
        *c.cc.epoque().unwrap() = 1000;
        c.dernier_envoi = HEURE;
        c.ack.lrcvtime = HEURE;
        c.ack.ato = 40 * MS;
        c.ack.pingpong = 0;
        c
    };
    let t = HEURE + 100 * MS;
    let mut c = prete();
    c.segment_de_donnees_parti(t);
    assert_eq!(*c.cc.epoque().unwrap(), 1000 + 25, "cent ms : 25 tics");
    assert_eq!(c.dernier_envoi, t);
    assert_eq!(c.ack.pingpong, 0, "plus de 40 ms après");
    // Quelque chose en vol : le silence n'en est pas un.
    let mut c = prete();
    en_vol(&mut c, 1);
    *c.cc.epoque().unwrap() = 1000;
    c.dernier_envoi = HEURE;
    c.segment_de_donnees_parti(t);
    assert_eq!(*c.cc.epoque().unwrap(), 1000);
    // Moins d'un `ato` après ce qui est arrivé : une conversation ; tout juste, non.
    let mut c = prete();
    c.segment_de_donnees_parti(HEURE + 40 * MS - 1);
    assert_eq!(c.ack.pingpong, 1);
    let mut c = prete();
    c.segment_de_donnees_parti(HEURE + 40 * MS);
    assert_eq!(c.ack.pingpong, 0);
}

/// PSH : seulement le dernier de ce qui est écrit, jamais un FIN seul. Le FIN seul n'est pas une
/// donnée (`tcp_event_data_sent`).
#[test]
fn psh_et_fin() {
    let mut c = etablie(true);
    c.reglages.nodelay = true;
    ecrits(&mut c, 2 * MSS as usize + 5);
    let v = sortants(&mut c, HEURE + MS);
    assert_eq!(v.iter().map(|h| h.drapeaux & tcp::PSH).collect::<Vec<_>>(), [0, 0, tcp::PSH]);
    assert_eq!(c.dernier_envoi, HEURE + MS);
    let mut c = etablie(true);
    c.dernier_envoi = 7;
    c.fermer_envoi();
    let v = sortants(&mut c, HEURE);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].drapeaux, tcp::ACK | tcp::FIN);
    assert_eq!(c.dernier_envoi, 7, "pas une donnée");
}

/// Le RTO n'est réarmé que par le premier segment en vol, ou s'il remplace une sonde de fin de rafale.
#[test]
fn le_rto_d_un_segment_neuf() {
    let lancer = |c: &mut C| c.envoyer_donnees(5, false, HEURE, false, &mut |_| {});
    let prete = || {
        let mut c = etablie(true);
        en_vol(&mut c, 1);
        ecrits(&mut c, 10);
        c
    };
    let mut c = prete();
    c.t_xmit = Some(1);
    c.t_sorte = Minuteur::Retransmission;
    assert!(lancer(&mut c));
    assert_eq!(c.t_xmit, Some(1), "un RTO court déjà");
    let mut c = prete();
    c.t_xmit = None;
    c.t_sorte = Minuteur::SondeDePerte;
    assert!(lancer(&mut c));
    assert_eq!(c.t_xmit, None, "plus rien d'armé : on n'arme pas ici");
    let mut c = prete();
    c.t_xmit = Some(1);
    c.t_sorte = Minuteur::SondeDePerte;
    assert!(lancer(&mut c));
    assert_ne!(c.t_xmit, Some(1), "la sonde laisse la place au RTO");
}

/// Un RST qui ne ferme pas (la réponse à un segment refusé) n'empêche pas le reste de partir.
#[test]
fn un_rst_et_la_suite() {
    let mut c = etablie(true);
    c.rst_du = Some((5, 0, tcp::RST));
    c.ack_maintenant = true;
    let v = sortants(&mut c, HEURE);
    assert_eq!(v.iter().map(|h| h.drapeaux).collect::<Vec<_>>(), [tcp::RST, tcp::ACK]);
    // Fermée : le RST, et rien d'autre.
    let mut c = etablie(true);
    c.etat = Etat::Fermee;
    c.rst_du = Some((5, 0, tcp::RST));
    c.ack_maintenant = true;
    let v = sortants(&mut c, HEURE);
    assert_eq!(v.iter().map(|h| h.drapeaux).collect::<Vec<_>>(), [tcp::RST]);
}

/// Seul le premier SYN est chronométré ; un SYN-ACK porte un ACK, pas un SYN.
#[test]
fn les_syn_qui_partent() {
    let mut c: C = Tcb::connecter(80, 40000, ISS, MSS as u16, 131_072, 1 << 22, 0);
    c.ack.programme = true;
    sortants(&mut c, HEURE);
    assert_eq!(c.syn_envoi, Some(HEURE));
    assert_eq!(c.retrans_stamp, HEURE);
    assert!(c.ack.programme, "un SYN seul ne porte pas d'ACK");
    for (retransmissions, total) in [(1, 0), (0, 1)] {
        let mut c: C = Tcb::connecter(80, 40000, ISS, MSS as u16, 131_072, 1 << 22, 0);
        c.retransmissions = retransmissions;
        c.total_retrans = total;
        sortants(&mut c, HEURE);
        assert_eq!((c.syn_envoi, c.retrans_stamp), (None, 0));
    }
    let mut c = fille(false);
    c.syn_du = true;
    c.ack.programme = true;
    let v = sortants(&mut c, HEURE);
    assert_eq!(v[0].drapeaux, tcp::SYN | tcp::ACK);
    assert!(!c.ack.programme, "le SYN-ACK l'a porté");
}

/// `tcp_chrono_start` : occupée seulement s'il y a du neuf à envoyer.
#[test]
fn le_chrono_de_l_occupation() {
    let plus_tard = HEURE + 1000 * MS;
    let mut c = etablie(true);
    sortants(&mut c, HEURE);
    assert_eq!(c.info(plus_tard).occupe, 0);
    let mut c = etablie(true);
    ecrits(&mut c, 10);
    sortants(&mut c, HEURE);
    assert_eq!(c.info(plus_tard).occupe, 1_000_000);
}

/// La sonde de fenêtre qui porte des données : le FIN, s'il reste de la place après le dernier octet.
#[test]
fn la_sonde_et_le_fin() {
    let prete = |ecrit: usize, fenetre: u32| {
        let mut c = etablie(true);
        c.reglages.nodelay = true;
        ecrits(&mut c, ecrit);
        c.fin_voulue = true;
        c.snd_wnd = fenetre;
        c.sonde_due = true;
        let v = sortants(&mut c, HEURE);
        v[0].drapeaux & tcp::FIN != 0
    };
    assert!(prete(10, 100), "de la place : le FIN aussi");
    assert!(!prete(10, 10), "tout juste le texte");
    assert!(!prete(2000, 1500), "un MSS, il en reste");
    assert!(!prete(20, 10), "la fenêtre coupe");
}

/// Sans rien à envoyer, `tcp_write_xmit` n'est même pas appelé.
#[test]
fn rien_a_envoyer_ne_valide_pas_la_cwnd() {
    let mut c = etablie(true);
    en_vol(&mut c, 2);
    c.cc.cwnd = 2;
    assert!(!c.cc.limitee());
    sortants(&mut c, HEURE);
    assert!(!c.cc.limitee());
}

/// RFC 2861 : après plus d'un RTO de silence, la cwnd repart de plus bas ; tout juste un RTO, non.
#[test]
fn le_silence_et_la_cwnd() {
    let essai = |silence: u64| {
        let mut c = etablie(true);
        c.reglages.nodelay = true;
        c.rto = 1000 * MS;
        c.cc.cwnd = 40;
        c.cc.ssthresh = 10;
        c.dernier_envoi = HEURE;
        // (Un programme qui attend : `tcp_cwnd_validate` ne la réduit pas de son côté.)
        c.sans_place = true;
        ecrits(&mut c, 10);
        sortants(&mut c, HEURE + silence);
        (c.cc.cwnd, c.cc.ssthresh)
    };
    assert_eq!(essai(1000 * MS), (40, 10));
    // Le seuil garde la trace de la cwnd : les trois quarts.
    assert_eq!(essai(1000 * MS + 1), (20, 30));
}

/// `tcp_cwnd_validate`, et ce que compte une réduction.
#[test]
fn apres_avoir_emis() {
    let tard = HEURE + 10_000 * MS;
    // Une cwnd large, jamais remplie : elle redescend, si rien n'est à reprendre.
    let prete = || {
        let mut c = etablie(true);
        c.cc.cwnd = 100;
        c.cc.ssthresh = 10;
        c.rto = 1000 * MS;
        c
    };
    let mut c = prete();
    c.apres_xmit(1, tard);
    assert_eq!(c.cc.cwnd, (100 + CWND_INITIALE) >> 1);
    // Rien de parti, sans être limitée : on ne valide pas.
    let mut c = prete();
    c.apres_xmit(0, tard);
    assert_eq!(c.cc.cwnd, 100);
    // Une orpheline, un programme qui attend, une reprise : on n'y touche pas.
    let mut c = prete();
    c.reglages.orpheline = true;
    c.apres_xmit(1, tard);
    assert_eq!(c.cc.cwnd, 100);
    let mut c = prete();
    c.sans_place = true;
    c.apres_xmit(1, tard);
    assert_eq!(c.cc.cwnd, 100);
    let mut c = prete();
    c.cc.phase = Phase::Reprise;
    c.apres_xmit(1, tard);
    assert_eq!(c.cc.cwnd, 100);
    // Les segments partis pendant une réduction (`tcp_cwnd_reduction`).
    let mut c = prete();
    c.cc.phase = Phase::Reprise;
    c.prr_sortis = 3;
    c.apres_xmit(2, tard);
    assert_eq!(c.prr_sortis, 5);
    let mut c = prete();
    c.prr_sortis = 3;
    c.apres_xmit(2, tard);
    assert_eq!(c.prr_sortis, 3);
}

/// `tcp_v4_send_reset`.
#[test]
fn la_reponse_sans_connexion() {
    let t = Tcp { source: 1, destination: 2, seq: 100, ack: 700, ..Tcp::default() };
    let r = reponse_sans_connexion(&Tcp { drapeaux: tcp::ACK, ..t }, 5).unwrap();
    assert_eq!((r.seq, r.ack, r.drapeaux), (700, 0, tcp::RST));
    assert_eq!((r.source, r.destination), (2, 1));
    let sans_ack = |drapeaux: u8, n: usize| {
        let r = reponse_sans_connexion(&Tcp { drapeaux, ..t }, n).unwrap();
        assert_eq!((r.seq, r.drapeaux), (0, tcp::RST | tcp::ACK));
        r.ack
    };
    assert_eq!(sans_ack(0, 5), 105);
    assert_eq!(sans_ack(tcp::FIN, 5), 106);
    assert_eq!(sans_ack(tcp::SYN, 5), 106);
    assert_eq!(sans_ack(tcp::SYN | tcp::FIN, 5), 107);
    assert_eq!(reponse_sans_connexion(&Tcp { drapeaux: tcp::RST, ..t }, 5), None);
}
