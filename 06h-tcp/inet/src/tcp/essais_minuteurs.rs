//! Les minuteurs d'une connexion et ce qu'ils décident (`tcp_keepalive_timer`,
//! `tcp_delack_timer_handler`, les erreurs ICMP, les ACK qui partent) : chaque test pose l'état juste
//! à la borne, et lit l'échéance, en ns, d'après les formules de Linux.

use super::essais::*;
use super::*;

/// Une erreur ICMP : son numéro ne compte pas ici (EHOSTUNREACH).
const ICMP_ERREUR: i32 = 113;

/// `tcp_event_ack_sent` : un ACK rapide de moins ; le dernier remet `ato` au minimum.
#[test]
fn un_ack_part() {
    let essai = |rapides: u32, programme: bool| {
        let mut c = etablie(true);
        c.ack.rapides = rapides;
        c.ack.programme = programme;
        c.ack.ato = 100 * MS;
        c.ack_envoye();
        (c.ack.rapides, c.ack.ato)
    };
    assert_eq!(essai(2, true), (1, 100 * MS));
    assert_eq!(essai(1, true), (0, ATO_MIN));
    assert_eq!(essai(0, true), (0, 100 * MS), "plus d'ACK rapide à compter");
    assert_eq!(essai(2, false), (2, 100 * MS), "cet ACK n'était pas dû");
}

/// `tcp_v4_err` : pour une connexion fermée ou en TIME_WAIT, rien.
#[test]
fn une_erreur_icmp_trop_tard() {
    for etat in [Etat::Fermee, Etat::TempsAttente] {
        for recverr in [false, true] {
            let mut c = etablie(true);
            c.etat = etat;
            assert_eq!(c.erreur_icmp(ICMP_ERREUR, 0, false, recverr, HEURE), Effets::default());
            assert_eq!((c.erreur, c.erreur_douce), (0, 0), "{etat:?}");
        }
    }
    let mut c = etablie(true);
    c.erreur_icmp(ICMP_ERREUR, 0, false, false, HEURE);
    assert_eq!((c.erreur, c.erreur_douce), (0, ICMP_ERREUR), "établie : une erreur douce");
    let mut c = etablie(true);
    let e = c.erreur_icmp(ICMP_ERREUR, 0, false, true, HEURE);
    assert_eq!(c.erreur, ICMP_ERREUR);
    assert!(e.lisible && e.place);
}

/// L'échéance qui ne peut pas attendre un tic de la roue : seulement l'ACK comprimé.
#[test]
fn l_echeance_fine() {
    let mut c = etablie(true);
    c.t_xmit = Some(HEURE);
    assert_eq!(c.echeance_fine(), None);
    c.t_comprime = Some(HEURE + 7);
    assert_eq!(c.echeance_fine(), Some(HEURE + 7));
    assert_eq!(c.echeance(), Some(HEURE));
}

/// L'ACK comprimé est échu : un de moins à comprimer, et il part ; s'il n'y en a plus, rien.
#[test]
fn l_ack_comprime_est_echu() {
    let essai = |comprimes: u32| {
        let mut c = etablie(true);
        c.ack_comprimes = comprimes;
        c.t_comprime = Some(HEURE);
        let e = c.minuteur(HEURE);
        assert_eq!(c.t_comprime, None);
        (c.ack_comprimes, c.ack_maintenant, e.a_emettre)
    };
    assert_eq!(essai(3), (2, true, true));
    assert_eq!(essai(1), (0, true, true));
    assert_eq!(essai(0), (0, false, false));
}

/// `tcp_keepalive_timer`, à ses bornes.
#[test]
fn le_keepalive() {
    let (idle, intvl) = (100 * MS, 10 * MS);
    let prete = || {
        let mut c = etablie(true);
        c.reglages.keepalive = true;
        c.reglages.keepidle = idle;
        c.reglages.keepintvl = intvl;
        c.reglages.keepcnt = 3;
        c.dernier_recu = HEURE;
        c.ack.lrcvtime = HEURE;
        c.t_keepalive = Some(HEURE);
        c
    };
    let lancer = |c: &mut C, t: u64| {
        let mut e = Effets::default();
        c.minuteur_keepalive(t, &mut e);
        e
    };
    let t = HEURE + idle;
    // Pas demandé, ou plus rien à garder : rien.
    let mut c = prete();
    c.reglages.keepalive = false;
    c.t_keepalive = None;
    assert_eq!(lancer(&mut c, t), Effets::default());
    assert_eq!((c.t_keepalive, c.sonde_due), (None, false));
    for etat in [Etat::Fermee, Etat::SynEnvoye, Etat::TempsAttente] {
        let mut c = prete();
        c.etat = etat;
        c.t_keepalive = None;
        assert_eq!(lancer(&mut c, t), Effets::default());
        assert_eq!((c.t_keepalive, c.sonde_due), (None, false), "{etat:?}");
    }
    // Du travail en cours : vivante sans lui : un TCP_KEEPIDLE de plus. En vol, ou à envoyer.
    let mut c = prete();
    en_vol(&mut c, 1);
    assert_eq!(lancer(&mut c, t), Effets::default());
    assert_eq!(c.t_keepalive, Some(t + idle));
    let mut c = prete();
    c.reglages.nodelay = true;
    c.ecrire::<()>(10, |d| {
        d.fill(1);
        Ok(())
    })
    .unwrap();
    assert!(c.file.is_empty());
    lancer(&mut c, t);
    assert_eq!(c.t_keepalive, Some(t + idle));
    assert!(!c.sonde_due);
    // Pas assez de silence : le reste du délai.
    let mut c = prete();
    lancer(&mut c, t - 30 * MS);
    assert_eq!(c.t_keepalive, Some(t));
    assert!(!c.sonde_due);
    // Le silence : une sonde, et la suivante dans TCP_KEEPINTVL.
    let mut c = prete();
    let e = lancer(&mut c, t);
    assert!(e.a_emettre && c.sonde_due);
    assert_eq!(c.sondes, 1);
    assert_eq!(c.t_keepalive, Some(t + intvl));
    // Encore assez d'essais : une de plus ; TCP_KEEPCNT sans réponse : coupée.
    let mut c = prete();
    c.sondes = 2;
    lancer(&mut c, t);
    assert_eq!(c.sondes, 3);
    assert_eq!(c.etat(), Etat::Etablie);
    let mut c = prete();
    c.sondes = 3;
    let e = lancer(&mut c, t);
    assert!(e.a_emettre && c.rst_actif && c.rst_du.is_some());
    assert_eq!((c.etat(), c.erreur), (Etat::Fermee, ETIMEDOUT));
    // TCP_USER_TIMEOUT remplace le compte : après au moins une sonde, et une fois le délai passé.
    let avec_delai = |sondes: u32, delai: u64| {
        let mut c = prete();
        c.reglages.delai_utilisateur = delai;
        c.sondes = sondes;
        c
    };
    let mut c = avec_delai(1, idle);
    lancer(&mut c, t);
    assert_eq!(c.etat(), Etat::Fermee, "tout juste le délai");
    let mut c = avec_delai(0, idle);
    lancer(&mut c, t);
    assert_eq!(c.etat(), Etat::Etablie, "pas encore de sonde");
    assert_eq!(c.sondes, 1);
    let mut c = avec_delai(1, idle + 1);
    lancer(&mut c, t);
    assert_eq!(c.etat(), Etat::Etablie, "le délai n'est pas passé");
    let mut c = avec_delai(9, idle + 1);
    lancer(&mut c, t);
    assert_eq!(c.etat(), Etat::Etablie, "plus de TCP_KEEPCNT");
}

/// `tcp_delack_timer_handler`.
#[test]
fn l_ack_retarde_est_echu() {
    let prete = |pingpong: u8| {
        let mut c = etablie(true);
        c.ack.programme = true;
        c.ack.pingpong = pingpong;
        c.ack.ato = 100 * MS;
        c.rto = 1000 * MS;
        c
    };
    let lancer = |c: &mut C| {
        let mut e = Effets::default();
        c.minuteur_ack(&mut e);
        e
    };
    // Trop court : il double, au plus le RTO.
    let mut c = prete(0);
    assert!(lancer(&mut c).a_emettre && c.ack_maintenant);
    assert_eq!(c.ack.ato, 200 * MS);
    let mut c = prete(0);
    c.rto = 150 * MS;
    lancer(&mut c);
    assert_eq!(c.ack.ato, 150 * MS);
    // La conversation a cessé : le minimum.
    let mut c = prete(2);
    assert!(lancer(&mut c).a_emettre);
    assert_eq!((c.ack.pingpong, c.ack.ato), (0, ATO_MIN));
    // Rien de dû, ou fermée : rien.
    let mut c = prete(0);
    c.ack.programme = false;
    assert_eq!(lancer(&mut c), Effets::default());
    assert_eq!(c.ack.ato, 100 * MS);
    let mut c = prete(0);
    c.etat = Etat::Fermee;
    assert_eq!(lancer(&mut c), Effets::default());
}

/// Ce que son écoute lit et pose d'une fille (`reqsk_timer_handler`, `essais_de_filles`).
#[test]
fn ce_que_l_ecoute_voit_d_une_fille() {
    let mut c = etablie(true);
    c.retransmissions = 0;
    assert!(c.fille_jeune());
    c.retransmissions = 1;
    assert!(!c.fille_jeune());
    c.essais_reduits = 9;
    c.reduire_essais(3);
    assert_eq!(c.essais_reduits, 3);
}
