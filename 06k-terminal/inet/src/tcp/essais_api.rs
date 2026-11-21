//! Ce que le noyau lit et demande d'une connexion (`tcp.rs`) : l'octet urgent, MSG_PEEK et
//! SO_PEEK_OFF, FIONREAD, le MSS, la MTU, `lu`, `ecrire`. `linux/tcp.c` vérifie tout cela de bout en
//! bout, contre Linux, sous QEMU ; ces tests posent l'état et regardent la bibliothèque seule : aux
//! bornes, et sans démarrer une machine (les mutants de `cargo mutants` ne verraient rien sinon).

use super::essais::*;
use super::*;
use alloc::vec;
use alloc::vec::Vec;

/// Un segment de l'autre, de `n` octets à partir de RCV.NXT + `decalage`.
fn segment(c: &C, decalage: u32, drapeaux: u8) -> Tcp {
    Tcp { seq: c.rcv_nxt.wrapping_add(decalage), ack: c.snd_una, drapeaux: tcp::ACK | drapeaux, fenetre: 65535, ..Tcp::default() }
}

/// `n` octets reçus dans l'ordre, valant 0, 1, 2...
fn recus(c: &mut C, n: usize) {
    let t = segment(c, 0, 0);
    let o: Vec<u8> = (0..n).map(|i| i as u8).collect();
    c.recevoir(&t, Octets(o, 0, 576 + n), HEURE);
    assert_eq!(c.octets_reception, n);
}

/// Lit `n` octets : ce qui est copié.
fn lire(c: &mut C, debut: &mut usize, n: usize, garder: bool) -> Vec<u8> {
    let mut v = Vec::new();
    c.lire_depuis::<()>(debut, n, garder, |m| {
        v.extend_from_slice(m);
        Ok(m.len())
    })
    .unwrap();
    v
}

/// La marque urgente posée `devant` octets après ce qui est lu.
fn avec_urgent(n: usize, devant: u32) -> C {
    let mut c = etablie(true);
    recus(&mut c, n);
    c.urg_seq = c.rcv_lu.wrapping_add(devant);
    c.urgent = Urgent::Valide(0x55);
    c
}

#[test]
fn les_constantes_de_linux() {
    assert_eq!(RCVBUF_MAX, 32 * 1024 * 1024);
    assert_eq!(PAWS_MSL, 60_000_000_000);
    let r = etablie(true).reglages;
    assert_eq!((r.keepidle, r.keepintvl, r.keepcnt), (7200 * 1_000_000_000, 75 * 1_000_000_000, 9));
    assert!(Info::sans_connexion(&Restes::NEUF, 0).debit_limite);
    assert_eq!(etablie(true).undo_retrans, -1);
}

/// `tcp_select_initial_window`, l'échelle ; les valeurs mesurées sur l'hôte.
#[test]
fn l_echelle_proposee() {
    let m = 1 << 20;
    // Sans SO_RCVBUF : d'après `tcp_rmem[2]`, le plafond seulement s'il est posé.
    assert_eq!(echelle(128 * 1024, false, 6 * m, 0), 7);
    assert_eq!(echelle(128 * 1024, false, 6 * m, m as u32), 5);
    // SO_RCVBUF fixé : la moitié, si le plafond n'est pas plus petit.
    assert_eq!(echelle(8 * m, true, 32 * m, 0), 7);
    assert_eq!(echelle(8 * m, true, 32 * m, (16 * m) as u32), 7);
    assert_eq!(echelle(8 * m, true, 32 * m, m as u32), 5);
    // Tout petit : 0.
    assert_eq!(echelle(1000, true, 32 * m, 0), 0);
}

/// `tcp_in_window`.
#[test]
fn dans_la_fenetre_() {
    let (d, f) = (1000, 2000);
    assert!(dans_la_fenetre(d, d, d, f), "vide, au bord gauche");
    assert!(dans_la_fenetre(d, d + 5, d, f));
    assert!(dans_la_fenetre(d - 5, d + 1, d, f), "à cheval à gauche");
    assert!(!dans_la_fenetre(d - 5, d, d, f), "fini au bord gauche");
    assert!(dans_la_fenetre(f - 1, f + 5, d, f));
    assert!(dans_la_fenetre(f, f, d, f), "vide, au bord droit");
    assert!(!dans_la_fenetre(f, f + 1, d, f), "pas vide, au bord droit");
    assert!(!dans_la_fenetre(f + 1, f + 1, d, f));
}

#[test]
fn les_etats_de_linux() {
    let cas = [
        (Etat::Etablie, 1, true, true),
        (Etat::SynEnvoye, 2, false, false),
        (Etat::SynRecu, 3, false, false),
        (Etat::FinAttente1, 4, true, true),
        (Etat::FinAttente2, 5, true, true),
        (Etat::TempsAttente, 6, true, false),
        (Etat::Fermee, 7, false, false),
        (Etat::AttenteFermeture, 8, true, false),
        (Etat::DernierAck, 9, true, false),
        (Etat::Fermeture, 11, true, false),
    ];
    for (e, n, sync, recoit) in cas {
        assert_eq!((e.linux(), e.synchronise(), e.recoit()), (n, sync, recoit), "{e:?}");
    }
}

#[test]
fn des_effets_cumules() {
    let tout = Effets { lisible: true, place: true, etat: true, a_emettre: true, ..Effets::default() };
    let mut e = Effets::default();
    e.ou(tout);
    assert!(e.lisible && e.place && e.etat && e.a_emettre);
    e.ou(Effets::default());
    assert!(e.lisible && e.place && e.etat && e.a_emettre, "rien n'efface");
}

#[test]
fn reprendre_les_horodatages() {
    let mut c = etablie(true);
    let vieux = Horodatages { recent: 7, instant: 8, decalage: 9 };
    c.reprendre_horodatages(vieux);
    assert!(c.ts.is_none());
    c.ts = Some(Horodatages { recent: 0, instant: 0, decalage: 3 });
    c.reprendre_horodatages(vieux);
    assert_eq!(c.ts, Some(Horodatages { recent: 7, instant: 8, decalage: 3 }), "le décalage reste le sien");
}

#[test]
fn le_controle_de_congestion() {
    let mut c = etablie(true);
    c.poser_controle(Controle::Reno);
    assert_eq!(c.controle(), Controle::Reno);
    // Sur une connexion en route, le nouveau s'initialise tout de suite ; fermée, non.
    assert!(!c.cc.initialise(), "à sa naissance : pas encore");
    c.prior_ssthresh = 5;
    c.choisir_controle(Controle::Cubic, HEURE);
    assert_eq!(c.prior_ssthresh, 0);
    assert!(c.cc.initialise());
    let mut c = etablie(true);
    c.etat = Etat::Fermee;
    c.poser_controle(Controle::Reno);
    c.choisir_controle(Controle::Cubic, HEURE);
    assert!(!c.cc.initialise());
    // Le même : rien.
    let mut c = etablie(true);
    c.prior_ssthresh = 5;
    c.choisir_controle(c.controle(), HEURE);
    assert_eq!(c.prior_ssthresh, 5);
}

/// Sans échelle de l'autre : aucune, et un plafond de 65 535 s'il y en a un.
#[test]
fn accepter_l_echelle() {
    let mut c = etablie(true);
    c.window_clamp = 1 << 20;
    c.accepter_echelle(None);
    assert_eq!(c.window_clamp, FENETRE_MAX);
    assert!(!c.echelle_ok);
    c.window_clamp = 0;
    c.accepter_echelle(None);
    assert_eq!(c.window_clamp, 0);
    c.accepter_echelle(Some(20));
    assert_eq!(c.echelle_envoi, ECHELLE_MAX);
    assert!(c.echelle_ok);
}

/// `tcp_v4_mtu_reduced`.
#[test]
fn la_mtu_reduite() {
    let prete = || {
        let mut c = etablie(true);
        c.mss_route = 1460;
        c
    };
    // Plus bas que la route, et DF : une erreur douce.
    for (info, mtu, df, attendu) in [(500, 576, true, EMSGSIZE), (576, 576, true, 0), (600, 576, true, 0), (500, 576, false, 0)] {
        let mut c = prete();
        c.mtu_reduite(info, mtu, df, false);
        assert_eq!(c.erreur_douce, attendu, "{info} {mtu} {df}");
    }
    // Sous ce qu'on suppose : le MSS suit, en vol et trop gros : perdu ; tout juste : rien.
    let mut c = prete();
    assert!(c.mtu_reduite(1400, 1400, true, true).a_emettre);
    assert_eq!(c.mss_route, 1360);
    let mut c = prete();
    assert!(c.mtu_reduite(1499, 1499, true, true).a_emettre, "un octet de moins suffit");
    assert_eq!(c.mss_route, 1459);
    let mut c = prete();
    assert!(!c.mtu_reduite(1500, 1500, true, true).a_emettre);
    assert_eq!(c.mss_route, 1460);
    let mut c = prete();
    assert!(!c.mtu_reduite(1400, 1400, true, false).a_emettre, "IP_PMTUDISC_DONT");
    assert_eq!(c.mss_route, 1460);
    // Fermée : rien du tout.
    let mut c = prete();
    c.etat = Etat::Fermee;
    assert!(!c.mtu_reduite(500, 576, true, true).a_emettre);
    assert_eq!(c.erreur_douce, 0);
}

/// `tcp_current_mss` : dans les deux sens, tant que la MTU change.
#[test]
fn verifier_la_mtu() {
    let mut c = etablie(true);
    c.mss_route = 1460;
    c.mss = 777;
    c.verifier_mtu(1500);
    assert_eq!((c.mss_route, c.mss), (1460, 777), "rien de neuf : rien");
    c.verifier_mtu(1400);
    assert_eq!(c.mss_route, 1360);
    assert_ne!(c.mss, 777);
    c.verifier_mtu(9000);
    assert_eq!(c.mss_route, 8960);
}

#[test]
fn le_mss_hors_de_l_etablissement() {
    // Le SYN parti (`tcp_connect_init`) : 536 moins les horodatages, ou TCP_MAXSEG moins
    // eux (mesuré : 524, 988) ; rien d'attendu de l'autre (88).
    let mut c: C = Tcb::connecter(&MIB, 80, 40000, ISS, 65_495, 131_072, 1 << 22, 0);
    c.proposer_horodatages(0);
    c.emettre(HEURE, |_| {});
    assert_eq!((c.mss(), c.ack.rcv_mss, c.mss_local), (524, 88, 65_495));
    let mut c: C = Tcb::connecter(&MIB, 80, 40000, ISS, 65_495, 131_072, 1 << 22, 0);
    c.proposer_horodatages(0);
    c.mss_utilisateur = 1000;
    c.emettre(HEURE, |_| {});
    assert_eq!((c.mss(), c.mss_local), (988, 1000));
    let r = c.restes();
    assert_eq!((r.mss, r.pmtu, r.entete, r.advmss, r.rcv_mss), (988, 65_535, 32, 1000, 88));
    // Finie : TCP_MAXSEG lui-même, s'il est posé.
    c.etat = Etat::Fermee;
    assert_eq!(c.mss(), 1000);
    c.mss_utilisateur = 0;
    assert_eq!(c.mss(), 988);
}

#[test]
fn les_options_ip_prennent_leur_place() {
    // IP_OPTIONS de 12 octets (mesuré) : 512 en SYN_SENT au lieu de 524, 976 avec
    // TCP_MAXSEG 1000 ; retirées, 988.
    let mut c: C = Tcb::connecter(&MIB, 80, 40000, ISS, 65_495, 131_072, 1 << 22, 0);
    c.proposer_horodatages(0);
    c.poser_options_ip(12);
    c.emettre(HEURE, |_| {});
    assert_eq!(c.mss(), 512);
    let mut c: C = Tcb::connecter(&MIB, 80, 40000, ISS, 65_495, 131_072, 1 << 22, 0);
    c.proposer_horodatages(0);
    c.mss_utilisateur = 1000;
    c.poser_options_ip(12);
    c.emettre(HEURE, |_| {});
    assert_eq!(c.mss(), 976);
    c.poser_options_ip(0);
    assert_eq!(c.mss(), 988);
    // Le plancher : 48 octets, avant les horodatages.
    c.mss_route = 60;
    c.poser_options_ip(40);
    assert_eq!(c.mss, MSS_ENVOI_MIN - TS_ALIGNE);
    // Sans connexion : 68, puis 36 après une connexion avec horodatages.
    let mut r = Restes::NEUF;
    r.synchroniser();
    assert_eq!(r.mss, 68);
    r.entete = 32;
    r.synchroniser();
    assert_eq!(r.mss, 36);
}

#[test]
fn l_offre_bornee_par_tcp_maxseg() {
    // Le SYN-ACK n'offre rien : TCP_MAXSEG reste la borne (`tcp_parse_options` ignore
    // aussi une offre nulle) ; il offre plus : TCP_MAXSEG ; moins : l'offre.
    let mut c = syn_envoye();
    c.mss_utilisateur = 700;
    c.mss_clamp = 700;
    c.mss_offre = Some(0);
    c.borner_par_l_offre();
    assert_eq!(c.mss_clamp, 700);
    c.mss_offre = Some(900);
    c.borner_par_l_offre();
    assert_eq!(c.mss_clamp, 700);
    c.mss_offre = Some(600);
    c.borner_par_l_offre();
    assert_eq!(c.mss_clamp, 600);
    c.synchroniser_mss();
    assert_eq!(c.mss, 600 - if c.ts.is_some() { TS_ALIGNE } else { 0 });
}

/// `tcp_bound_to_half_wnd`.
#[test]
fn le_mss_borne_par_la_fenetre() {
    let mut c = etablie(true);
    c.mss = 10_000;
    c.max_fenetre = 0;
    assert_eq!(c.mss_borne(), 10_000, "aucune fenêtre vue");
    // Une fenêtre de plus de 536 : la moitié ; tout juste 536 : elle-même.
    c.max_fenetre = 1000;
    assert_eq!(c.mss_borne(), 500);
    c.max_fenetre = MSS_DEFAUT as u32;
    assert_eq!(c.mss_borne(), MSS_DEFAUT as u32);
    c.max_fenetre = MSS_DEFAUT as u32 + 1;
    assert_eq!(c.mss_borne(), (MSS_DEFAUT as u32 + 1) / 2);
    // Le plancher : 68 octets moins les en-têtes (48), moins les horodatages (36).
    c.max_fenetre = 10;
    assert_eq!(c.mss_borne(), 48);
    c.ts = Some(Horodatages { recent: 0, instant: 0, decalage: 0 });
    assert_eq!(c.mss_borne(), 36);
    // Tout juste la coupure : le MSS, même sous le plancher.
    c.mss = 500;
    c.max_fenetre = 1000;
    assert_eq!(c.mss_borne(), 500);
    c.ts = None;
    c.mss = 20;
    c.max_fenetre = 20;
    assert_eq!(c.mss_borne(), 20);
}

/// FIONREAD : ce qui précède la marque, si l'octet urgent est hors du flux.
#[test]
fn fionread_et_la_marque() {
    let c = avec_urgent(10, 4);
    assert_eq!(c.lisibles_fionread(), 4);
    assert_eq!(avec_urgent(10, 10).lisibles_fionread(), 10, "pas encore là");
    assert_eq!(avec_urgent(10, 9).lisibles_fionread(), 9);
    let mut c = avec_urgent(10, 4);
    c.reglages.oobinline = true;
    assert_eq!(c.lisibles_fionread(), 10);
    let mut c = avec_urgent(10, 4);
    c.urgent = Urgent::Aucun;
    assert_eq!(c.lisibles_fionread(), 10);
    let mut c = avec_urgent(10, 4);
    c.etat = Etat::SynRecu;
    assert_eq!(c.lisibles_fionread(), 0);
}

/// `tcp_stream_is_readable` : l'octet urgent en tête, hors du flux, ne compte pas.
#[test]
fn lisibles_et_la_marque() {
    let c = avec_urgent(10, 0);
    assert!(c.a_la_marque());
    assert_eq!(c.lisibles_dans_le_flux(), 9);
    assert_eq!(c.lisibles_depuis(0), 9);
    assert_eq!(c.lisibles_depuis(3), 7);
    assert!(c.a_la_marque_depuis(0));
    assert!(!c.a_la_marque_depuis(1));
    let c = avec_urgent(10, 3);
    assert!(!c.a_la_marque());
    assert_eq!(c.lisibles_dans_le_flux(), 10);
    assert_eq!(c.lisibles_depuis(3), 6);
    assert!(c.a_la_marque_depuis(3));
    // En ligne, il compte.
    let mut c = avec_urgent(10, 0);
    c.reglages.oobinline = true;
    assert!(c.a_la_marque());
    assert_eq!(c.lisibles_dans_le_flux(), 10);
    assert_eq!(c.lisibles_depuis(0), 10);
    // Pas de marque.
    let mut c = avec_urgent(10, 0);
    c.urgent = Urgent::Aucun;
    assert!(!c.a_la_marque() && !c.a_la_marque_depuis(0));
    assert_eq!(c.lisibles_depuis(0), 10);
    assert_eq!(c.lisibles_depuis(20), 0, "au-delà de la file");
    // La marque au bout de ce qui est reçu, l'octet pas encore là.
    let c = avec_urgent(10, 10);
    assert!(!c.a_la_marque_depuis(10));
    assert_eq!(c.lisibles_depuis(10), 0);
    let mut c = etablie(true);
    c.urg_seq = c.rcv_lu;
    c.urgent = Urgent::Attendu;
    assert!(!c.a_la_marque());
}

/// `tcp_urg` et ses compteurs ; ce que voit SIOCATMARK.
#[test]
fn quelques_lectures_d_etat() {
    let mut c = avec_urgent(10, 0);
    assert!(c.urgent_a_lire());
    c.urgent = Urgent::Lu;
    assert!(!c.urgent_a_lire());
    c.urgents_annonces = 3;
    assert_eq!(c.urgents_annonces(), 3);
    assert_eq!(c.numero_lu(), c.rcv_lu);
    c.erreur = 9;
    assert_eq!(c.erreur(), 9);
    assert_eq!(c.erreur, 9, "sans l'effacer");
    // `tcp_poll` : pas de marque si rien n'est là.
    let mut c = etablie(true);
    c.urg_seq = c.rcv_lu;
    c.urgent = Urgent::Lu;
    assert!(!c.a_la_marque());
    recus(&mut c, 1);
    assert!(c.a_la_marque());
}

/// `tcp_recv_urg`.
#[test]
fn lire_l_octet_urgent() {
    let mut c = avec_urgent(10, 0);
    assert_eq!(c.lire_urgent(true), Ok(Some(0x55)));
    assert_eq!(c.urgent, Urgent::Valide(0x55), "regardé, pas lu");
    assert_eq!(c.lire_urgent(false), Ok(Some(0x55)));
    assert_eq!(c.urgent, Urgent::Lu);
    assert_eq!(c.lire_urgent(false), Err(EINVAL), "déjà lu");
    // Le pointeur vu, pas encore l'octet. Coupée sans FIN.
    let attendu = || {
        let mut c = etablie(true);
        c.urgent = Urgent::Attendu;
        c
    };
    let mut c = attendu();
    c.etat = Etat::Fermee;
    assert_eq!(c.lire_urgent(false), Err(ENOTCONN));
    // Coupée après un FIN, ou le FIN reçu : rien de plus à lire.
    c.fin_recue = true;
    assert_eq!(c.lire_urgent(false), Ok(None));
    let mut c = attendu();
    c.fin_recue = true;
    assert_eq!(c.lire_urgent(false), Ok(None));
    assert_eq!(attendu().lire_urgent(false), Err(EAGAIN));
}

/// MSG_PEEK, SO_PEEK_OFF : le décalage avance, l'octet urgent sauté compris, sur plusieurs morceaux.
#[test]
fn regarder_sans_retirer() {
    let mut c = etablie(true);
    recus(&mut c, 4);
    let t = segment(&c, 0, 0);
    c.recevoir(&t, Octets(vec![10, 11, 12], 0, 600), HEURE);
    let (lu, oc) = (c.rcv_lu, c.octets_reception);
    let mut d = 0;
    assert_eq!(lire(&mut c, &mut d, 2, true), vec![0, 1]);
    assert_eq!(d, 2);
    assert_eq!(lire(&mut c, &mut d, 3, true), vec![2, 3, 10]);
    assert_eq!(d, 5);
    assert_eq!(lire(&mut c, &mut d, 9, true), vec![11, 12]);
    assert_eq!(d, 7);
    assert!(lire(&mut c, &mut d, 9, true).is_empty());
    assert_eq!((c.rcv_lu, c.octets_reception), (lu, oc), "rien de retiré");
    // Le décalage tout juste au bout d'un morceau : le suivant.
    let mut d = 4;
    assert_eq!(lire(&mut c, &mut d, 1, true), vec![10]);
    // L'octet urgent au décalage : sauté, et compté dans ce qui avance.
    let mut c = avec_urgent(6, 2);
    let mut d = 0;
    assert_eq!(lire(&mut c, &mut d, 9, true), vec![0, 1], "arrêté à la marque");
    assert_eq!(d, 2);
    assert_eq!(lire(&mut c, &mut d, 9, true), vec![3, 4, 5]);
    assert_eq!(d, 6);
    // En ligne : lu comme un autre.
    let mut c = avec_urgent(6, 2);
    c.reglages.oobinline = true;
    let mut d = 2;
    assert_eq!(lire(&mut c, &mut d, 9, true), vec![2, 3, 4, 5]);
}

/// Une lecture qui retire : à la marque, l'octet urgent s'en va d'abord, et la marque passée s'oublie.
#[test]
fn lire_et_la_marque() {
    let mut c = avec_urgent(6, 2);
    let mut d = 0;
    assert_eq!(lire(&mut c, &mut d, 9, false), vec![0, 1]);
    assert_eq!(c.urgent, Urgent::Valide(0x55), "la marque devant");
    assert_eq!(lire(&mut c, &mut d, 9, false), vec![3, 4, 5]);
    assert_eq!(c.urgent, Urgent::Aucun, "la marque est passée");
    assert_eq!(c.octets_reception, 0);
    // Tout juste à la marque : elle reste jusqu'à ce qu'on la dépasse.
    let mut c = avec_urgent(6, 0);
    c.reglages.oobinline = true;
    assert_eq!(lire(&mut c, &mut 0, 1, false), vec![0]);
    assert_eq!(c.urgent, Urgent::Aucun);
    let mut c = avec_urgent(6, 3);
    c.reglages.oobinline = true;
    assert_eq!(lire(&mut c, &mut 0, 3, false), vec![0, 1, 2]);
    assert_eq!(c.urgent, Urgent::Valide(0x55));
    // Sans octet dans la file, la marque n'arrête rien.
    let mut c = avec_urgent(3, 3);
    assert_eq!(lire(&mut c, &mut 0, 3, false), vec![0, 1, 2]);
    // En regardant : la marque tout au bout, pas encore d'octet à sauter : le décalage reste.
    let mut c = avec_urgent(3, 3);
    let mut d = 3;
    assert!(lire(&mut c, &mut d, 9, true).is_empty());
    assert_eq!(d, 3);
}

/// Une copie qui s'arrête, ou qui échoue après des octets déjà pris.
#[test]
fn une_copie_qui_s_arrete() {
    // Courte : le reste reste.
    let mut c = etablie(true);
    recus(&mut c, 4);
    let n = c.lire_depuis::<()>(&mut 0, 4, false, |m| Ok(m.len().min(3))).unwrap();
    assert_eq!((n, c.octets_reception), (3, 1));
    // En regardant, de même, sans rien retirer.
    let mut c = etablie(true);
    recus(&mut c, 4);
    let t = segment(&c, 0, 0);
    c.recevoir(&t, Octets(vec![9], 0, 600), HEURE);
    let mut d = 0;
    let n = c.lire_depuis::<()>(&mut d, 9, true, |m| Ok(m.len().min(3))).unwrap();
    assert_eq!((n, d, c.octets_reception), (3, 3, 5));
    // Tout juste la longueur du morceau : on passe au suivant.
    let mut d = 0;
    let n = c.lire_depuis::<()>(&mut d, 9, true, |m| Ok(m.len())).unwrap();
    assert_eq!((n, d), (5, 5));
    // L'erreur, seulement si rien n'a été lu.
    let mut c = etablie(true);
    recus(&mut c, 4);
    let t = segment(&c, 0, 0);
    c.recevoir(&t, Octets(vec![9], 0, 600), HEURE);
    assert_eq!(c.lire::<u8>(9, false, |_| Err(7)), Err(7));
    let mut fois = 0;
    let r = c.lire::<u8>(9, false, |m| {
        fois += 1;
        if fois == 1 { Ok(m.len()) } else { Err(7) }
    });
    assert_eq!(r, Ok(4));
}

/// MSG_TRUNC : jeté, compté.
#[test]
fn jeter_() {
    let mut c = etablie(true);
    recus(&mut c, 4);
    assert_eq!(c.jeter(3), 3);
    assert_eq!(c.octets_reception, 1);
    assert_eq!(c.jeter(3), 1);
}

/// `tcp_cleanup_rbuf`, après une lecture.
#[test]
fn l_ack_apres_une_lecture() {
    let prete = || {
        let mut c = etablie(true);
        c.ack.rcv_mss = 1000;
        c.rcv_wup = c.rcv_nxt;
        // (L'annonce dépasse la moitié du plafond : le test de la fenêtre qui double ne joue pas.)
        c.window_clamp = 1 << 16;
        c.rcv_wnd = 1 << 16;
        c.ack.programme = true;
        c.ack.pousse = 0;
        c.ack.pingpong = 1;
        c.rcvbuf = 1 << 20;
        c.rcv_ssthresh = 1 << 20;
        c
    };
    // Plus d'un MSS non annoncé : tout de suite ; tout juste un MSS : non.
    let mut c = prete();
    c.rcv_wup = c.rcv_nxt.wrapping_sub(1001);
    assert!(c.lu(0, HEURE).a_emettre);
    let mut c = prete();
    c.rcv_wup = c.rcv_nxt.wrapping_sub(1000);
    assert!(!c.lu(0, HEURE).a_emettre);
    // Rien de prévu : ni l'un, ni l'autre.
    let mut c = prete();
    c.ack.programme = false;
    c.rcv_wup = c.rcv_nxt.wrapping_sub(1001);
    assert!(!c.lu(0, HEURE).a_emettre);
    // Poussé, tout lu, quelque chose de copié.
    let mut c = prete();
    c.ack.pousse = ACK_POUSSE2;
    assert!(c.lu(1, HEURE).a_emettre, "POUSSE2");
    let mut c = prete();
    c.ack.pousse = ACK_POUSSE2;
    assert!(!c.lu(0, HEURE).a_emettre, "rien de copié");
    let mut c = prete();
    c.ack.pousse = ACK_POUSSE;
    assert!(!c.lu(1, HEURE).a_emettre, "POUSSE, en ping-pong");
    let mut c = prete();
    c.ack.pousse = ACK_POUSSE;
    c.ack.pingpong = 0;
    assert!(c.lu(1, HEURE).a_emettre);
    let mut c = prete();
    c.ack.pousse = 0;
    c.ack.pingpong = 0;
    assert!(!c.lu(1, HEURE).a_emettre, "rien de poussé");
    let mut c = prete();
    c.ack.pousse = ACK_POUSSE2;
    recus(&mut c, 10);
    c.ack.programme = true;
    c.ack.pousse = ACK_POUSSE2;
    c.rcv_wup = c.rcv_nxt;
    assert!(!c.lu(1, HEURE).a_emettre, "il reste à lire");
    // Pas synchronisée : rien, sauf SYN_RECV.
    let mut c = prete();
    c.etat = Etat::Fermee;
    c.rcv_wup = c.rcv_nxt.wrapping_sub(1001);
    assert!(!c.lu(0, HEURE).a_emettre);
    let mut c = prete();
    c.etat = Etat::SynRecu;
    c.rcv_wup = c.rcv_nxt.wrapping_sub(1001);
    assert!(c.lu(0, HEURE).a_emettre);
}

/// `__tcp_cleanup_rbuf` : la fenêtre a au moins doublé ; pas après le FIN, ni si rien n'est copié.
#[test]
fn l_ack_quand_la_fenetre_double() {
    let prete = |annoncee: u32| {
        let mut c = etablie(true);
        c.ack.programme = false;
        c.ack.rcv_mss = 100;
        c.window_clamp = 1 << 20;
        c.rcvbuf = 1 << 20;
        c.rcv_ssthresh = 8000;
        c.rcv_wup = c.rcv_nxt;
        c.rcv_wnd = annoncee;
        c.echelle_reception = 0;
        c
    };
    let neuve = prete(0).choisir_fenetre();
    assert_eq!(neuve, 8000);
    assert!(prete(4000).lu(1, HEURE).a_emettre, "tout juste le double");
    assert!(!prete(4001).lu(1, HEURE).a_emettre);
    assert!(prete(100).lu(1, HEURE).a_emettre);
    assert!(!prete(100).lu(0, HEURE).a_emettre, "rien de copié");
    let mut c = prete(100);
    c.fin_recue = true;
    assert!(!c.lu(1, HEURE).a_emettre);
    let mut c = prete(100);
    c.lecture_fermee = true;
    assert!(!c.lu(1, HEURE).a_emettre);
    // L'annonce dépasse la moitié du plafond : on ne regarde pas plus loin.
    let mut c = prete(4000);
    c.window_clamp = 7999;
    assert!(!c.lu(1, HEURE).a_emettre);
    let mut c = prete(4000);
    c.window_clamp = 8000;
    assert!(c.lu(1, HEURE).a_emettre);
    // Une fenêtre choisie nulle : rien.
    let mut c = prete(0);
    c.rcvbuf = 0;
    assert!(!c.lu(1, HEURE).a_emettre);
}

/// `sk_wmem_schedule`, et SIOCOUTQ.
#[test]
fn la_place_et_ce_qui_reste() {
    let mut c = etablie(true);
    c.sndbuf = 1000;
    assert_eq!(c.place(), 1000);
    c.octets_envoi = 400;
    assert_eq!(c.place(), 600);
    c.memoire = Memoire::Limite;
    assert_eq!(c.place(), 0);
    c.octets_envoi = 0;
    assert_eq!(c.place(), 1000, "un tampon vide passe toujours");
    // Au-delà de la juste part : `tcp_wmem[0]` reste garanti.
    c.memoire = Memoire::Excedent;
    c.sndbuf = 1 << 20;
    c.octets_envoi = WMEM0 - 1;
    assert_eq!(c.place(), (1 << 20) - WMEM0 + 1);
    c.octets_envoi = WMEM0;
    assert_eq!(c.place(), 0);
    // La mémoire de la connexion, les deux sens.
    let mut c = etablie(true);
    recus(&mut c, 4);
    let r = c.memoire_reception();
    assert!(r > 0);
    assert_eq!(c.memoire(), r);
    c.octets_envoi = 7;
    assert_eq!(c.memoire(), r + 7);
    // SIOCOUTQ : rien pendant la poignée de main.
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    assert_eq!(c.non_acquittes(), MSS as usize);
    c.etat = Etat::SynRecu;
    c.syn_acquitte = false;
    assert_eq!(c.non_acquittes(), 0);
    assert_eq!(c.non_envoyes(), 0);
}

#[test]
fn les_files_d_une_connexion_finie() {
    // Une poignée de main qui échoue : SIOCOUTQ compte le SYN (mesuré : 1) ; /proc/net/tcp,
    // dès SYN_SENT.
    let mut c = syn_envoye();
    assert_eq!((c.non_acquittes(), c.a_acquitter()), (0, 1));
    c.etat = Etat::Fermee;
    assert_eq!(c.non_acquittes(), 1);
    // Deux segments en vol, trois qui attendent (la fenêtre de congestion), puis un RST : les
    // files sont jetées, les numéros restent, et le chronomètre court encore.
    let mut c = etablie(true);
    en_vol(&mut c, 2);
    c.cc.cwnd = 2;
    assert_eq!(c.ecrire::<()>(3 * MSS as usize, |d| {
        d.fill(2);
        Ok(())
    }), Ok(3 * MSS as usize));
    c.emettre(HEURE, |_| {});
    let (a, n) = (c.a_acquitter(), c.non_envoyes());
    assert_eq!((a, n, c.non_acquittes()), (5 * MSS, 3 * MSS as usize, 5 * MSS as usize));
    c.recevoir(&segment(&c, 0, tcp::RST), octets(0, 0), HEURE + MS);
    assert_eq!(c.etat(), Etat::Fermee);
    assert_eq!((c.a_acquitter(), c.non_envoyes(), c.non_acquittes(), c.file.len(), c.octets_envoi), (a, n, a as usize, 0, 0));
    let (occupe, _, _) = c.mesures.chronos(HEURE + MS);
    let (plus_tard, _, _) = c.mesures.chronos(HEURE + 1000 * MS);
    assert!(plus_tard >= occupe + 900_000, "{occupe} {plus_tard}");
    // Rien en file : le chronomètre s'arrête avec la connexion.
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    let ack = Tcp { ack: c.snd_nxt, ..segment(&c, 0, 0) };
    c.recevoir(&ack, octets(0, 0), HEURE + MS);
    c.recevoir(&segment(&c, 0, tcp::RST), octets(0, 0), HEURE + 2 * MS);
    assert_eq!(c.mesures.chronos(HEURE + 2 * MS), c.mesures.chronos(HEURE + 1000 * MS));
}

#[test]
fn ce_que_garde_une_socket_deconnectee() {
    // Une connexion qui a échangé : deux segments acquittés (un RTT mesuré), trois octets reçus.
    let mut c = etablie(true);
    en_vol(&mut c, 2);
    let ack = Tcp { ack: c.snd_nxt, ..segment(&c, 0, 0) };
    c.recevoir(&ack, octets(0, 0), HEURE + 5 * MS);
    recus(&mut c, 3);
    c.reordering = 7;
    c.retransmissions = 2;
    c.rehash = 4;
    let avant = c.info(HEURE + 10 * MS);
    let w = c.write_seq();
    let r = c.restes().deconnecte(HEURE + 10 * MS);
    let i = Info::sans_connexion(&r, HEURE + 20 * MS);
    // Gardé (mesuré sous Linux 6.18).
    assert_eq!((i.retransmissions, i.reordonnancement, i.rehash), (2, 7, 4));
    assert_eq!(
        (i.rcv_ssthresh, i.rcv_space, i.pacing, i.snd_wnd, i.rcv_wnd, i.min_rtt, i.snd_mss, i.advmss, i.pmtu),
        (avant.rcv_ssthresh, avant.rcv_space, avant.pacing, avant.snd_wnd, avant.rcv_wnd, avant.min_rtt, avant.snd_mss, avant.advmss, avant.pmtu)
    );
    assert!(i.min_rtt < u32::MAX && i.rcv_space > 0);
    assert_eq!((i.debit, i.debit_limite), (avant.debit, true));
    assert_eq!((i.dernier_envoi, i.dernier_ack, i.dernier_recu), (avant.dernier_envoi + 10, avant.dernier_ack + 10, 0));
    // Remis par `tcp_disconnect`.
    assert_eq!((i.etat, i.rcv_mss, i.rto, i.rttvar, i.cwnd, i.rtt, i.segs_out, i.total_retrans), (7, 88, 1_000_000, 250_000, CWND_INITIALE, 0, 0, 0));
    // La suite des numéros : un saut de la plus grande fenêtre de l'autre, plus 2, à chaque fois.
    let saut = c.max_fenetre + 2;
    assert_eq!((r.numero_de_depart(), i.non_envoyes, r.non_acquittes(), r.non_envoyes()), (Some(w + saut), saut, saut, saut));
    assert_eq!(r.deconnecte(HEURE + 30 * MS).numero_de_depart(), Some(w + 2 * saut));
    // Une socket neuve : un numéro neuf ; défaite (une écoute, mesuré) : 2.
    assert_eq!(Restes::NEUF.numero_de_depart(), None);
    assert_eq!(Restes::NEUF.deconnecte(HEURE).numero_de_depart(), Some(2));
    // Refusée en SYN_SENT (mesuré : SIOCOUTQ 3, SIOCOUTQNSD 2, notsent 2).
    let mut c = syn_envoye();
    c.recevoir(&Tcp { ack: ISS + 1, drapeaux: tcp::RST | tcp::ACK, ..Tcp::default() }, octets(0, 0), HEURE + MS);
    assert_eq!(c.etat(), Etat::Fermee);
    let r = c.restes().deconnecte(HEURE + MS);
    assert_eq!((r.non_acquittes(), r.non_envoyes(), Info::sans_connexion(&r, HEURE + MS).non_envoyes), (3, 2, 2));
    // Une écoute après : le débit de l'envoi et le réordonnancement gardés.
    let mut r = Restes::NEUF;
    r.pacing = 12_345;
    r.reordering = 9;
    let i = Info::ecoute(0, 4, &r);
    assert_eq!((i.etat, i.pacing, i.reordonnancement, i.cwnd), (10, 12_345, 9, CWND_INITIALE));
}

#[test]
fn le_chronometre_d_une_socket_deconnectee() {
    // Rien en file : il s'arrête à la déconnexion.
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    let ack = Tcp { ack: c.snd_nxt, ..segment(&c, 0, 0) };
    c.recevoir(&ack, octets(0, 0), HEURE + MS);
    let r = c.restes().deconnecte(HEURE + 2 * MS);
    assert_eq!(r.mesures.chronos(HEURE + 2 * MS), r.mesures.chronos(HEURE + 1000 * MS));
    // Des données en vol : il court encore ; une seconde déconnexion, les files vides
    // désormais, l'arrête.
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    let r = c.restes().deconnecte(HEURE + MS);
    let (a, _, _) = r.mesures.chronos(HEURE + MS);
    let (b, _, _) = r.mesures.chronos(HEURE + 1000 * MS);
    assert!(b >= a + 900_000, "{a} {b}");
    let r = r.deconnecte(HEURE + 1000 * MS);
    assert_eq!(r.mesures.chronos(HEURE + 1000 * MS), r.mesures.chronos(HEURE + 2000 * MS));
}

#[test]
fn la_reprise_d_une_socket() {
    // Ce que la connexion suivante reprend (mesuré : le plus petit RTT, le débit livré, le
    // rehachage), et ce qu'elle remet (les retransmissions).
    let mut c = etablie(true);
    en_vol(&mut c, 2);
    let ack = Tcp { ack: c.snd_nxt, ..segment(&c, 0, 0) };
    c.recevoir(&ack, octets(0, 0), HEURE + 5 * MS);
    c.rehash = 3;
    c.reordering = 5;
    c.retransmissions = 2;
    let r = c.restes().deconnecte(HEURE + 10 * MS);
    let iss = r.numero_de_depart().unwrap();
    let mut n: C = Tcb::connecter(&MIB, 80, 40000, iss, MSS as u16, 131_072, 1 << 22, 0);
    n.reprendre(&r);
    n.emettre(HEURE + 20 * MS, |_| {});
    let i = n.info(HEURE + 20 * MS);
    let a = Info::sans_connexion(&r, HEURE + 20 * MS);
    assert_eq!((i.etat, i.min_rtt, i.rehash, i.reordonnancement, i.pacing, i.rcv_space, i.dernier_envoi), (2, a.min_rtt, 3, 5, a.pacing, a.rcv_space, a.dernier_envoi));
    assert_eq!((i.debit, i.debit_limite, i.retransmissions), (r.mesures.debit(n.mss_borne()), true, 0));
    assert!(i.min_rtt < u32::MAX && i.debit > 0);
    assert_eq!(n.snd_una, iss);
}

#[test]
fn le_hachage_change_a_chaque_rto() {
    // Le SYN : chaque RTO qui n'abandonne pas (mesuré : 3 après trois SYN renvoyés).
    let mut c = syn_envoye();
    for k in 1..=3 {
        let t = c.t_xmit.unwrap();
        c.minuteur(t);
        assert_eq!((c.rehash, c.total_rto), (k, k));
    }
    assert_eq!(c.info(HEURE).rehash, 3);
    // Une fille : une requête, qui n'a pas de hachage à changer.
    let mut c = fille(false);
    let t = c.t_xmit.unwrap();
    c.minuteur(t);
    assert_eq!((c.retransmissions, c.rehash), (1, 0));
    // Établie : de même (le RTO, pas la sonde de fin de rafale) ; la sonde d'une fenêtre
    // fermée, non.
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    c.t_sorte = Minuteur::Retransmission;
    let t = c.t_xmit.unwrap();
    c.minuteur(t);
    assert_eq!((c.total_rto, c.rehash), (1, 1));
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    c.snd_wnd = 0;
    c.t_sorte = Minuteur::Retransmission;
    let t = c.t_xmit.unwrap();
    c.minuteur(t);
    assert_eq!((c.recul, c.total_rto, c.rehash), (1, 0, 0));
    // SO_TXREHASH 0 : les RTO se comptent, le hachage ne change plus.
    let mut c = syn_envoye();
    c.txrehash = false;
    for k in 1..=2 {
        let t = c.t_xmit.unwrap();
        c.minuteur(t);
        assert_eq!((c.rehash, c.total_rto), (0, k));
    }
    let mut c = etablie(true);
    c.txrehash = false;
    en_vol(&mut c, 1);
    c.t_sorte = Minuteur::Retransmission;
    let t = c.t_xmit.unwrap();
    c.minuteur(t);
    assert_eq!((c.total_rto, c.rehash), (1, 0));
}

#[test]
fn le_fin_dans_la_file_de_reception() {
    // /proc/net/tcp compte le FIN (`rcv_nxt - copied_seq`) jusqu'à ce qu'une lecture le passe ;
    // MSG_PEEK ne le passe pas.
    let mut c = etablie(true);
    recus(&mut c, 3);
    c.recevoir(&segment(&c, 0, tcp::FIN), octets(0, 0), HEURE);
    assert_eq!(c.en_reception(), 4);
    let mut debut = 0;
    assert_eq!(lire(&mut c, &mut debut, 2, false).len(), 2);
    c.lecture_finie();
    assert_eq!(c.en_reception(), 2);
    assert_eq!(lire(&mut c, &mut debut, 8, false).len(), 1);
    c.lecture_finie();
    assert_eq!(c.en_reception(), 0);
    // Le FIN après les données lues : la lecture qui rend 0 le passe.
    let mut c = etablie(true);
    c.lecture_finie();
    c.recevoir(&segment(&c, 0, tcp::FIN), octets(0, 0), HEURE);
    assert_eq!(c.en_reception(), 1);
    c.lecture_finie();
    assert_eq!(c.en_reception(), 0);
}

/// `tcp_new_space` : SO_SNDBUF ne suit que si la cwnd n'est pas pleine.
#[test]
fn verifier_la_place() {
    let prete = |en_vol_: usize, cwnd: u32| {
        let mut c = etablie(true);
        en_vol(&mut c, en_vol_);
        c.sans_place = true;
        c.cc.cwnd = cwnd;
        c.sndbuf = 16 * 1024;
        c
    };
    let mut c = prete(2, 3);
    let b = c.sndbuf;
    c.verifier_place(HEURE);
    assert!(c.sndbuf > b, "de la place dans la cwnd");
    let mut c = prete(2, 2);
    let b = c.sndbuf;
    c.verifier_place(HEURE);
    assert_eq!(c.sndbuf, b, "la cwnd tout juste pleine");
    // Un tiers libre, tout juste : il n'attend plus.
    let mut c = prete(1, 1);
    c.sndbuf = 3 * MSS as usize / 2;
    c.sndbuf_fixe = true;
    c.verifier_place(HEURE);
    assert!(!c.sans_place);
    let mut c = prete(1, 1);
    c.sndbuf_fixe = true;
    c.sndbuf = MSS as usize + 1;
    c.verifier_place(HEURE);
    assert!(c.sans_place);
}

/// `ecrire` : la place, les blocs, la copie qui échoue.
#[test]
fn ecrire_() {
    // Tout juste la place : le programme ne devient pas « sans place ».
    let mut c = etablie(true);
    c.sndbuf = 100;
    assert_eq!(c.ecrire::<()>(100, |d| { d.fill(1); Ok(()) }), Ok(100));
    assert!(!c.sans_place);
    let mut c = etablie(true);
    c.sndbuf = 100;
    assert_eq!(c.ecrire::<()>(101, |d| { d.fill(1); Ok(()) }), Ok(100));
    assert!(c.sans_place);
    // Chaque bloc fait au plus BLOC ; ce qui est écrit après tient dans le dernier s'il reste de la place.
    let mut c = etablie(true);
    c.sndbuf = 10 * BLOC;
    let mut vus = Vec::new();
    assert_eq!(c.ecrire::<()>(BLOC + 10, |d| { vus.push(d.len()); d.fill(1); Ok(()) }), Ok(BLOC + 10));
    assert_eq!(vus, vec![BLOC, 10]);
    assert_eq!(c.envoi.back().unwrap().capacity(), 10, "pas plus que demandé");
    vus.clear();
    assert_eq!(c.ecrire::<()>(BLOC, |d| { vus.push(d.len()); d.fill(1); Ok(()) }), Ok(BLOC));
    assert_eq!(vus, vec![BLOC - 10, 10]);
    // La copie échoue : l'erreur si rien n'est écrit, sinon ce qui l'a été ; rien de plus ne reste.
    let mut c = etablie(true);
    c.sndbuf = 10 * BLOC;
    assert_eq!(c.ecrire::<u8>(5, |_| Err(9)), Err(9));
    assert_eq!(c.octets_envoi, 0);
    assert!(c.envoi.is_empty());
    let mut fois = 0;
    let r = c.ecrire::<u8>(BLOC + 5, |d| {
        fois += 1;
        if fois == 1 { d.fill(1); Ok(()) } else { Err(9) }
    });
    assert_eq!(r, Ok(BLOC));
    assert_eq!(c.octets_envoi, BLOC);
    assert_eq!(c.envoi.len(), 1);
}

/// Des octets acquittés en deux fois : le reste d'un bloc commencé compte, pas le bloc entier.
#[test]
fn acquitter_un_bloc_en_deux_fois() {
    let mut c = etablie(true);
    assert_eq!(c.ecrire::<()>(100, |d| { d.fill(1); Ok(()) }), Ok(100));
    c.acquitter_octets(10);
    assert_eq!((c.decalage_envoi, c.octets_envoi, c.envoi.len()), (10, 90, 1));
    c.acquitter_octets(90);
    assert_eq!((c.decalage_envoi, c.octets_envoi, c.envoi.len()), (0, 0, 0));
}

/// `close` en SYN_SENT : rien n'est parti que le SYN : fermée, sans FIN.
#[test]
fn fermer_avant_la_reponse() {
    let mut c = syn_envoye();
    let e = c.fermer_envoi();
    assert_eq!(c.etat(), Etat::Fermee);
    assert!(e.etat && !c.fin_voulue && !e.a_emettre);
}
