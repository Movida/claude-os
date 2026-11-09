//! Ce qu'un segment reçu fait à une connexion (`tcp.rs`, `recevoir` et ce qu'il appelle) : la fille
//! et `tcp_check_req`, PAWS et les ACK désordonnés, `tcp_ack`, le RTT du récepteur, les réglages,
//! TCP_INFO et le pointeur urgent. `tests/tcp.rs` et `linux/tcp.c` jouent ces scénarios de bout en
//! bout ; ici, chaque test pose l'état juste à la borne, là où le bout en bout ne regarde pas.

use super::essais::*;
use super::*;
use alloc::vec;

/// Un ACK pur de l'autre, au bord gauche, qui ne change rien.
fn ack_pur(c: &C) -> Tcp {
    Tcp { seq: c.rcv_nxt, ack: c.snd_una, drapeaux: tcp::ACK, fenetre: c.snd_wnd.min(65535) as u16, ..Tcp::default() }
}

/// Une connexion qui ne voit pas de changement de fenêtre dans `ack_pur`.
fn sans_mise_a_jour(sack: bool) -> C {
    let mut c = etablie(sack);
    c.snd_wnd = 65535;
    c.snd_wl1 = c.rcv_nxt;
    c
}

/// Un segment pour la fille `c`, dans la fenêtre, qui acquitte son SYN.
fn pour_fille(c: &C, drapeaux: u8) -> Tcp {
    Tcp { seq: c.rcv_nxt, ack: ISS + 1, drapeaux, fenetre: 65535, ..Tcp::default() }
}

/// L'ouverture simultanée : SYN_SENT, puis le SYN de l'autre, sans ACK : SYN_RECEIVED.
fn simultanee() -> C {
    let mut c: C = Tcb::connecter(80, 40000, ISS, MSS as u16, 131_072, 1 << 22, 0);
    c.emettre(HEURE, |_| {});
    let syn = Tcp { source: 40000, destination: 80, seq: 1000, drapeaux: tcp::SYN, fenetre: 65535, ..Tcp::default() };
    c.recevoir(&syn, octets(0, 0), HEURE);
    c.emettre(HEURE, |_| {});
    assert_eq!(c.etat(), Etat::SynRecu);
    assert!(!c.fille);
    c
}

fn sans_charge() -> Octets {
    octets(0, 0)
}

fn syn_ack(c: &C) -> Tcp {
    Tcp { source: 40000, destination: 80, seq: 1000, ack: c.snd_nxt, drapeaux: tcp::SYN | tcp::ACK, fenetre: 65535, ..Tcp::default() }
}

/// `tcp_acceptable_seq` : SND.NXT, sauf une fenêtre réduite de plus que l'arrondi de l'échelle.
#[test]
fn le_numero_d_un_segment_sans_donnees() {
    let mut c = etablie(true);
    en_vol(&mut c, 2);
    let (una, nxt) = (c.snd_una, c.snd_nxt);
    c.echelle_reception = 4;
    c.echelle_ok = true;
    for (fenetre, attendu) in [(3000, nxt), (2000, nxt), (2000 - 1, nxt), (2000 - 15, nxt), (2000 - 16, una + 1984), (2000 - 17, una + 1983)] {
        c.snd_wnd = fenetre;
        assert_eq!(c.seq_acceptable(), attendu, "fenêtre {fenetre}");
    }
    // Sans échelle : pas d'arrondi.
    c.echelle_ok = false;
    c.snd_wnd = 2000 - 5;
    assert_eq!(c.seq_acceptable(), una + 1995);
    c.snd_wnd = 2000;
    assert_eq!(c.seq_acceptable(), nxt);
}

/// `tcp_receive_window(tp) <= rcv_mss`, ou `tcp_rmem_pressure`.
#[test]
fn la_fenetre_presque_fermee() {
    let prete = |wnd: u32| {
        let mut c = etablie(true);
        c.rcvbuf = 1 << 20;
        c.ack.rcv_mss = 1000;
        c.rcv_wup = c.rcv_nxt;
        c.rcv_wnd = wnd;
        c
    };
    assert!(!prete(1001).fenetre_presque_fermee());
    assert!(prete(1000).fenetre_presque_fermee());
    assert!(prete(999).fenetre_presque_fermee());
    let mut c = prete(1 << 16);
    c.memoire = Memoire::Pression;
    assert!(c.fenetre_presque_fermee(), "la pression seule suffit");
}

/// `tcp_check_req` : l'estimation de `ts_recent_stamp` à l'heure du dernier SYN-ACK, un RTO en
/// arrière ; c'est elle qui décide si un RST relâche PAWS (60 s plus tard), pas zéro.
#[test]
fn la_fille_estime_l_heure_de_son_ts() {
    let tard = 100 * 1_000_000_000;
    let vieux = |drapeaux: u8, c: &C| Tcp { options: tcp::Options { horodatage: Some((400, 0)), ..tcp::Options::default() }, ..pour_fille(c, drapeaux) };
    // Un RST, vieux, avec un RTO ordinaire : rejeté ; `instant` à 0 l'aurait laissé passer.
    let mut c = fille(true);
    c.rto = 1_000_000_000;
    let t = vieux(tcp::RST, &c);
    c.recevoir(&t, sans_charge(), tard);
    assert_eq!(c.etat(), Etat::SynRecu);
    // Un RTO de plus de 60 s : le même RST passe...
    let mut c = fille(true);
    c.rto = 61 * 1_000_000_000;
    let t = vieux(tcp::RST, &c);
    c.recevoir(&t, sans_charge(), tard);
    assert_eq!(c.etat(), Etat::Fermee);
    // ... et un ACK aussi vieux reste rejeté : seul un RST est relâché.
    let mut c = fille(true);
    c.rto = 61 * 1_000_000_000;
    let t = vieux(tcp::ACK, &c);
    let e = c.recevoir(&t, sans_charge(), tard);
    assert_eq!(c.etat(), Etat::SynRecu);
    assert!(e.a_emettre && c.ack_maintenant, "un ACK en réponse");
    assert_eq!(c.mesures.segs_in, 0, "elle n'est pas née");
}

/// Le SYN répété : il compte comme une retransmission.
#[test]
fn la_fille_et_le_syn_repete() {
    let mut c = fille(false);
    c.total_retrans = 0;
    let t = Tcp { seq: c.irs, drapeaux: tcp::SYN, fenetre: 65535, ..Tcp::default() };
    let e = c.recevoir(&t, sans_charge(), HEURE);
    assert!(e.a_emettre && c.syn_du);
    assert_eq!(c.total_retrans, 1);
}

/// Hors de la fenêtre : un ACK, limité sauf pour des données ; jamais à un RST.
#[test]
fn la_fille_hors_de_la_fenetre() {
    let loin = |c: &C, drapeaux: u8| Tcp { seq: c.rcv_nxt + 400_000, ..pour_fille(c, drapeaux) };
    let limitee = || {
        let mut c = fille(false);
        c.dernier_ack_invalide = Some(HEURE);
        c
    };
    // Un RST : rien, limite ou pas.
    let mut c = fille(false);
    let t = loin(&c, tcp::RST | tcp::ACK);
    assert!(!c.recevoir(&t, sans_charge(), HEURE).a_emettre);
    // Des données : un ACK, même limité.
    let mut c = limitee();
    let t = loin(&c, tcp::ACK);
    assert!(c.recevoir(&t, octets(5, 600), HEURE).a_emettre);
    // Un ACK pur, limité : rien ; pas limité : un ACK.
    let mut c = limitee();
    let t = loin(&c, tcp::ACK);
    assert!(!c.recevoir(&t, sans_charge(), HEURE).a_emettre);
    let mut c = fille(false);
    let t = loin(&c, tcp::ACK);
    assert!(c.recevoir(&t, sans_charge(), HEURE).a_emettre);
    // Un SYN avec des données, limité : rien, ce n'est pas une donnée qu'on acquitte.
    let mut c = limitee();
    let t = Tcp { ack: 0, ..loin(&c, tcp::SYN) };
    assert!(!c.recevoir(&t, octets(5, 600), HEURE).a_emettre);
}

/// Le SYN d'origine dans un segment de la fenêtre (avec des données, pour y entrer) ne compte plus.
#[test]
fn la_fille_et_le_syn_d_origine_avec_des_donnees() {
    let mut c = fille(false);
    let t = Tcp { seq: c.irs, ..pour_fille(&c, tcp::SYN | tcp::ACK) };
    c.recevoir(&t, octets(1, 600), HEURE);
    assert_eq!(c.etat(), Etat::Etablie);
    assert_eq!(c.rst_du, None);
}

/// Sans ACK : la fille reste, et le segment ne la fait pas naître.
#[test]
fn la_fille_et_un_segment_sans_ack() {
    let mut c = fille(false);
    let t = pour_fille(&c, tcp::FIN);
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.etat(), Etat::SynRecu);
    assert_eq!(c.mesures.segs_in, 0, "elle compte à sa naissance");
    // Pour une fille, un segment rejeté ne compte pas non plus (`self.fille && SynRecu`).
    let mut c = fille(false);
    let t = Tcp { seq: c.rcv_nxt + 400_000, ..pour_fille(&c, tcp::ACK) };
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.mesures.segs_in, 0);
}

/// `tcp_send_dupack`.
#[test]
fn repondre_a_un_doublon() {
    let appel = |c: &mut C, seq: u32, n: u32, syn: bool| {
        let mut e = Effets::default();
        c.repondre_doublon(seq, n, syn, HEURE, &mut e);
        e
    };
    let prete = || {
        let mut c = etablie(true);
        c.ack.pingpong = 3;
        c.ack.rapides = 0;
        c.dernier_ack_invalide = Some(HEURE);
        c
    };
    // Des données déjà reçues : le mode rapide, un D-SACK, un ACK même limité.
    let mut c = prete();
    let seq = c.rcv_nxt - 10;
    assert!(appel(&mut c, seq, 4, false).a_emettre);
    assert_eq!(c.ack.pingpong, 0);
    assert_eq!(c.dsack, Some((seq, seq + 4)));
    // Rien de reçu : ni mode rapide, ni D-SACK, et la limite tient.
    let mut c = prete();
    let seq = c.rcv_nxt - 10;
    assert!(!appel(&mut c, seq, 0, false).a_emettre);
    assert_eq!((c.ack.pingpong, c.dsack), (3, None));
    // Un SYN : pareil.
    let mut c = prete();
    let seq = c.rcv_nxt - 10;
    assert!(!appel(&mut c, seq, 4, true).a_emettre);
    assert_eq!((c.ack.pingpong, c.dsack), (3, None));
    // À cheval sur le bord : le D-SACK s'arrête à RCV.NXT.
    let mut c = prete();
    let seq = c.rcv_nxt - 2;
    let nxt = c.rcv_nxt;
    appel(&mut c, seq, 4, false);
    assert_eq!(c.dsack, Some((seq, nxt)));
    // Devant le bord : pas de doublon, mais l'ACK part.
    let mut c = prete();
    let seq = c.rcv_nxt + 2;
    assert!(appel(&mut c, seq, 4, false).a_emettre);
    assert_eq!(c.dsack, None);
}

/// `tcp_disordered_ack_check` : TSval de moins d'un RTO en arrière, en unités de 1/1200 s.
#[test]
fn un_ack_desordonne() {
    let prete = || {
        let mut c = sans_mise_a_jour(true);
        c.rto = 1_000_000_000;
        c.ts = Some(Horodatages { recent: 5000, instant: HEURE, decalage: 0 });
        c
    };
    let c = prete();
    let t = ack_pur(&c);
    // Un RTO d'une seconde : 1200 unités.
    assert_eq!(c.ack_desordonne(&t, 5000 - 1200, t.seq), Desordonne::Accepte);
    assert_eq!(c.ack_desordonne(&t, 5000 - 1201, t.seq), Desordonne::Refuse);
    assert_eq!(c.ack_desordonne(&t, 5000, t.seq), Desordonne::Accepte);
    // Sans ACK, ou avec du texte.
    let sans = Tcp { drapeaux: 0, ..t };
    assert_eq!(c.ack_desordonne(&sans, 5000, t.seq), Desordonne::Refuse);
    assert_eq!(c.ack_desordonne(&t, 5000, t.seq + 1), Desordonne::Refuse);
    // Plus vieux que le bord : jeté sans réponse ; plus loin : refusé.
    let vieux = Tcp { seq: t.seq - 1, ..t };
    assert_eq!(c.ack_desordonne(&vieux, 5000, vieux.seq), Desordonne::VieilAck);
    let loin = Tcp { seq: t.seq + 1, ..t };
    assert_eq!(c.ack_desordonne(&loin, 5000, loin.seq), Desordonne::Refuse);
    // Il change la fenêtre, ou il acquitte : refusé. Sans horodatages : refusé.
    let fenetre = Tcp { fenetre: 0, ..t };
    assert_eq!(c.ack_desordonne(&fenetre, 5000, t.seq), Desordonne::Refuse);
    let mut c = prete();
    c.ts = None;
    assert_eq!(c.ack_desordonne(&t, 5000, t.seq), Desordonne::Refuse);
}

/// Une connexion fermée n'a plus rien à recevoir : le noyau répond à sa place.
#[test]
fn fermee_elle_ne_voit_rien() {
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    c.fille = false;
    c.etat = Etat::Fermee;
    let (una, segs) = (c.snd_una, c.mesures.segs_in);
    let t = Tcp { ack: fin(0), ..ack_pur(&c) };
    assert_eq!(c.recevoir(&t, sans_charge(), HEURE), Effets::default());
    assert_eq!((c.snd_una, c.mesures.segs_in), (una, segs));
}

/// Un ACK faux en SYN_SENT : notre RST, et le SYN repart vite, s'il n'a pas déjà été renvoyé.
#[test]
fn un_ack_faux_en_syn_envoye() {
    let mut c = syn_envoye();
    let t = Tcp { ack: ISS + 500, ..syn_ack(&c) };
    let e = c.recevoir(&t, sans_charge(), HEURE);
    assert!(e.a_emettre);
    assert_eq!(c.rst_du, Some((ISS + 500, 0, tcp::RST)));
    assert_eq!(c.t_xmit, Some(HEURE + 2 * sack::JIFFY));
    assert_eq!(c.etat(), Etat::SynEnvoye);
}

/// L'ACK de la poignée de main attend s'il peut être porté par des données
/// (`tcp_rcv_synsent_state_process`) ; chacune des trois raisons suffit.
#[test]
fn l_ack_de_la_poignee_de_main() {
    let essai = |poser: fn(&mut C)| {
        let mut c = syn_envoye();
        poser(&mut c);
        let t = syn_ack(&c);
        c.recevoir(&t, sans_charge(), HEURE);
        assert_eq!(c.etat(), Etat::Etablie);
        c
    };
    let c = essai(|_| {});
    assert!(c.ack_maintenant && !c.ack.programme && c.ack.t.is_none(), "rien pour le porter");
    for poser in [
        (|c: &mut C| c.ecrivains_en_attente = 1) as fn(&mut C),
        |c: &mut C| c.reglages.defer_accept = 1,
        |c: &mut C| c.ack.pingpong = 1,
    ] {
        let c = essai(poser);
        assert!(!c.ack_maintenant && c.ack.programme, "il attend");
        assert_eq!(c.ack.t, Some(HEURE + DELACK_MAX));
    }
}

/// Le bord droit d'un bloc SACK vaut le bord gauche, pour un RST (`tcp_validate_incoming`).
#[test]
fn un_rst_au_bord_du_sack() {
    let mut c = etablie(true);
    let nxt = c.rcv_nxt;
    c.blocs[0] = (nxt + 100, nxt + 200);
    c.blocs[1] = (nxt + 300, nxt + 400);
    c.nb_blocs = 2;
    let au = |c: &C, seq: u32| Tcp { seq, ..ack_pur(c) };
    let t = Tcp { drapeaux: tcp::RST, ..au(&c, nxt + 200) };
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.etat(), Etat::Etablie, "un autre bloc : un ACK de défi");
    let t = Tcp { drapeaux: tcp::RST, ..au(&c, nxt + 400) };
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.etat(), Etat::Fermee);
    assert_eq!(c.erreur, ECONNRESET);
}

/// L'ouverture simultanée : l'ACK doit porter sur notre SYN, ni moins ni plus.
#[test]
fn le_troisieme_ack_d_une_ouverture_simultanee() {
    for ack in [ISS + 2, ISS] {
        let mut c = simultanee();
        let t = Tcp { seq: c.rcv_nxt, ack, drapeaux: tcp::ACK, fenetre: 65535, ..Tcp::default() };
        let e = c.recevoir(&t, sans_charge(), HEURE);
        assert_eq!(c.etat(), Etat::SynRecu, "ack {ack}");
        assert!(e.a_emettre);
        assert_eq!(c.rst_du, Some((ack, 0, tcp::RST)));
    }
    let mut c = simultanee();
    let livres = c.livres;
    let t = Tcp { seq: c.rcv_nxt, ack: ISS + 1, drapeaux: tcp::ACK, fenetre: 65535, ..Tcp::default() };
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.etat(), Etat::Etablie);
    // Le SYN du client et le SYN-ACK de la fille : les deux à la fois.
    assert_eq!(c.livres, livres + 2);
}

/// Hors d'ESTABLISHED, c'est la suite de `tcp_rcv_state_process` qui répond à un ACK rejeté.
#[test]
fn un_ack_rejete_hors_d_etablie() {
    let prete = || {
        let mut c = etablie(true);
        en_vol(&mut c, 1);
        c.fermer_envoi();
        assert_eq!(c.etat(), Etat::FinAttente1);
        c
    };
    let au_dela = |c: &C| Tcp { ack: c.snd_nxt + 5, ..ack_pur(c) };
    let mut c = prete();
    let t = au_dela(&c);
    assert!(c.recevoir(&t, sans_charge(), HEURE).a_emettre);
    assert!(c.ack_maintenant);
    let mut c = prete();
    c.dernier_ack_invalide = Some(HEURE);
    let t = au_dela(&c);
    assert!(!c.recevoir(&t, sans_charge(), HEURE).a_emettre);
    // En ESTABLISHED : rien, sans limite à franchir.
    let mut c = etablie(true);
    en_vol(&mut c, 1);
    let t = au_dela(&c);
    assert!(!c.recevoir(&t, sans_charge(), HEURE).a_emettre);
}

/// FLAG_DATA : un segment de données au bord gauche n'est pas un ACK dupliqué.
#[test]
fn des_donnees_ne_sont_pas_un_doublon() {
    let mut c = sans_mise_a_jour(false);
    en_vol(&mut c, 5);
    c.snd_wnd = 65535;
    let t = ack_pur(&c);
    c.recevoir(&t, octets(10, 600), HEURE);
    assert_eq!(c.sacked_out, 0, "des données : pas un doublon");
    let t = ack_pur(&c);
    let wl1 = t.seq;
    c.snd_wl1 = wl1;
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.sacked_out, 1, "un ACK pur en est un");
}

/// Passé le FIN de l'autre ou la lecture fermée : des données neuves coupent ; un ACK pur, non.
#[test]
fn un_ack_pur_apres_la_lecture_fermee() {
    let mut c = etablie(true);
    c.etat = Etat::FinAttente2;
    c.lecture_fermee = true;
    let t = Tcp { seq: c.rcv_nxt + 100, ..ack_pur(&c) };
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.etat(), Etat::FinAttente2);
    assert_eq!(c.rst_du, None);
    let t = Tcp { seq: c.rcv_nxt + 100, ..ack_pur(&c) };
    c.recevoir(&t, octets(1, 600), HEURE);
    assert_eq!(c.etat(), Etat::Fermee);
    assert!(c.rst_du.is_some());
}

/// Un bloc SACK d'un pair qui n'a pas négocié SACK ne compte pas.
#[test]
fn des_blocs_sans_sack() {
    let mut c = sans_mise_a_jour(false);
    en_vol(&mut c, 3);
    let mut t = ack_pur(&c);
    t.options.nb_blocs = 1;
    t.options.blocs[0] = (debut(1), fin(1));
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.file[1].marques & retrans::SACKE, 0);
    // Négocié : il compte.
    let mut c = sans_mise_a_jour(true);
    en_vol(&mut c, 3);
    let mut t = ack_pur(&c);
    t.options.nb_blocs = 1;
    t.options.blocs[0] = (debut(1), fin(1));
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.sacked_out, 1);
}

/// RFC 5961 5.2 : un ACK d'avant tout ce qu'on a pu envoyer : un ACK de défi, limité.
#[test]
fn un_ack_a_l_aveugle() {
    let prete = || {
        let mut c = etablie(true);
        en_vol(&mut c, 3);
        let t = Tcp { ack: fin(2), ..ack_pur(&c) };
        c.recevoir(&t, sans_charge(), HEURE);
        c.max_fenetre = 100;
        c
    };
    let mut c = prete();
    let t = Tcp { ack: c.snd_una - 1000, ..ack_pur(&c) };
    assert!(c.recevoir(&t, sans_charge(), HEURE).a_emettre);
    let mut c = prete();
    c.dernier_ack_invalide = Some(HEURE);
    let t = Tcp { ack: c.snd_una - 1000, ..ack_pur(&c) };
    assert!(!c.recevoir(&t, sans_charge(), HEURE).a_emettre);
}

/// Un ACK déjà vu qui porte des blocs : ils valent encore (`tcp_ack`, `old_ack`), et ce qu'ils
/// disent atteint la reprise, avec les drapeaux qu'ils ont posés.
#[test]
fn un_vieil_ack_et_ses_blocs() {
    let prete = || {
        let mut c = etablie(true);
        en_vol(&mut c, 6);
        let t = Tcp { ack: fin(0), ..ack_pur(&c) };
        c.recevoir(&t, sans_charge(), HEURE);
        c.max_fenetre = 1 << 20;
        c.reordering = 3;
        c
    };
    let avec = |c: &C, blocs: &[(u32, u32)]| {
        let mut t = Tcp { ack: c.snd_una - 500, ..ack_pur(c) };
        t.options.nb_blocs = blocs.len() as u8;
        t.options.blocs[..blocs.len()].copy_from_slice(blocs);
        t
    };
    // Rien de perdu : rien à renvoyer.
    let mut c = prete();
    let t = avec(&c, &[(debut(2), fin(2))]);
    assert!(!c.recevoir(&t, sans_charge(), HEURE).a_emettre);
    assert_eq!(c.sacked_out, 1);
    // Assez de blocs : la perte est vue, il y a à renvoyer.
    let mut c = prete();
    let t = avec(&c, &[(debut(2), fin(5))]);
    let e = c.recevoir(&t, sans_charge(), HEURE + 100 * MS);
    assert_eq!(c.sacked_out, 4);
    assert!(e.a_emettre);
    assert_ne!(c.rexmit, Rexmit::Rien);
}

/// Les blocs d'un vieil ACK vont jusqu'à F-RTO : un segment jamais renvoyé, SACKé, prouve que la
/// perte était fausse (`FLAG_ORIG_SACK_ACKED`, RFC 5682).
#[test]
fn un_vieil_ack_et_f_rto() {
    let mut c = etablie(true);
    en_vol(&mut c, 6);
    let t = Tcp { ack: fin(0), ..ack_pur(&c) };
    c.recevoir(&t, sans_charge(), HEURE);
    c.max_fenetre = 1 << 20;
    c.entrer_perte(HEURE);
    c.frto = true;
    c.undo_marker = Some(c.snd_una);
    c.undo_retrans = 1;
    c.retrans_stamp = HEURE;
    let mut t = Tcp { ack: c.snd_una - 500, ..ack_pur(&c) };
    t.options.nb_blocs = 1;
    t.options.blocs[0] = (debut(4), fin(4));
    c.recevoir(&t, sans_charge(), HEURE);
    assert_ne!(c.cc.phase, Phase::Perte);
    assert_eq!(c.undo_marker, None);
}

/// `tcp_ack_is_dubious` : un ACK ordinaire n'entre pas dans `tcp_fastretrans_alert`, qui remet
/// `retrans_stamp` à zéro en état ouvert.
#[test]
fn un_ack_ordinaire_n_est_pas_douteux() {
    let mut c = etablie(true);
    en_vol(&mut c, 3);
    c.retrans_stamp = 123;
    let t = Tcp { ack: fin(0), ..ack_pur(&c) };
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.cc.phase, Phase::Ouverte);
    assert_eq!(c.retrans_stamp, 123);
    // Un ACK dupliqué, lui, y entre.
    let t = ack_pur(&c);
    c.snd_wl1 = t.seq;
    c.snd_wnd = t.fenetre as u32;
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.retrans_stamp, 0);
}

/// Dans l'alerte, seul un ACK qui n'apporte rien compte comme dupliqué : sans SACK, c'est lui qui
/// fait monter `sacked_out`.
#[test]
fn un_ack_qui_avance_n_est_pas_duplique() {
    let mut c = sans_mise_a_jour(false);
    en_vol(&mut c, 5);
    c.cc.phase = Phase::Desordre;
    c.sacked_out = 1;
    let t = Tcp { ack: fin(0), ..ack_pur(&c) };
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.sacked_out, 0, "oublié, et pas de doublon de plus");
    // Des données, sans avancée : pas un doublon non plus, même dans l'alerte.
    let mut c = sans_mise_a_jour(false);
    en_vol(&mut c, 5);
    c.cc.phase = Phase::Desordre;
    c.sacked_out = 1;
    let t = ack_pur(&c);
    c.recevoir(&t, octets(10, 600), HEURE);
    assert_eq!(c.sacked_out, 1);
}

/// Sans progrès, rien ne se réveille et rien ne part.
#[test]
fn un_ack_sans_progres() {
    let mut c = sans_mise_a_jour(true);
    en_vol(&mut c, 2);
    let t = ack_pur(&c);
    let e = c.recevoir(&t, sans_charge(), HEURE);
    assert!(!e.place, "rien de libéré");
    assert!(!e.a_emettre, "rien à envoyer");
    // Rien en vol non plus.
    let mut c = sans_mise_a_jour(true);
    let t = ack_pur(&c);
    let e = c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(e, Effets::default());
}

/// Le mode urgent finit quand l'octet urgent est acquitté : ni avant, ni pour un vieux.
#[test]
fn le_mode_urgent_de_l_emetteur() {
    let prete = || {
        let mut c = etablie(true);
        en_vol(&mut c, 3);
        c
    };
    let ack = |c: &mut C, jusqua: u32| {
        let t = Tcp { ack: jusqua, ..ack_pur(c) };
        c.recevoir(&t, sans_charge(), HEURE);
    };
    let mut c = prete();
    c.snd_up = fin(1);
    ack(&mut c, fin(0));
    assert_eq!(c.snd_up, fin(1), "pas encore");
    let mut c = prete();
    c.snd_up = fin(0) - 1;
    ack(&mut c, fin(0));
    assert_eq!(c.snd_up, fin(0));
    assert!(!c.mode_urgent());
    let mut c = prete();
    let vieux = c.snd_una - 10;
    c.snd_up = vieux;
    ack(&mut c, fin(0));
    assert_eq!(c.snd_up, vieux, "d'avant : on n'y touche pas");
}

/// Sans rien en vol, seul un D-SACK touche à la reprise (`tcp_ack`, `no_queue`).
#[test]
fn rien_en_vol_et_le_dsack() {
    let prete = |undo_retrans: i32| {
        let mut c = sans_mise_a_jour(true);
        c.cc.phase = Phase::Desordre;
        c.undo_marker = Some(c.snd_una - 2 * MSS);
        c.undo_retrans = undo_retrans;
        c
    };
    // Sans D-SACK : pas d'alerte, donc pas d'annulation, qui serait pourtant permise.
    let mut c = prete(0);
    let t = ack_pur(&c);
    c.recevoir(&t, sans_charge(), HEURE);
    assert!(c.undo_marker.is_some());
    assert_eq!(c.rack.persiste, 0);
    // Un D-SACK : un renvoi de moins à attendre, et `tcp_try_undo_dsack`.
    let mut c = prete(1);
    c.total_retrans = 1;
    let mut t = ack_pur(&c);
    t.options.nb_blocs = 1;
    t.options.blocs[0] = (c.snd_una - MSS, c.snd_una);
    c.recevoir(&t, sans_charge(), HEURE);
    assert_eq!(c.undo_retrans, 0);
    assert_eq!(c.rack.persiste, 1);
    assert!(c.undo_marker.is_none(), "annulée");
}

/// La fenêtre de l'autre ne réveille l'émetteur qu'en s'ouvrant de zéro.
#[test]
fn la_fenetre_de_l_autre_s_ouvre() {
    let mut c = etablie(true);
    c.snd_wnd = 1000;
    let t = Tcp { seq: c.snd_wl1 + 1, fenetre: 2000, ..Tcp::default() };
    let mut e = Effets::default();
    assert_eq!(c.maj_fenetre(&t, &mut e), FLAG_WIN_UPDATE);
    assert_eq!(c.snd_wnd, 2000);
    assert!(!e.a_emettre, "elle était ouverte");
    c.snd_wnd = 0;
    let t = Tcp { seq: c.snd_wl1 + 1, fenetre: 2000, ..Tcp::default() };
    let mut e = Effets::default();
    c.maj_fenetre(&t, &mut e);
    assert!(e.a_emettre);
}

/// `tcp_sndbuf_expand` : un MSS offert à 0 ne vaut pas, TCP_MAXSEG à 0 non plus ; 640 octets en plus.
#[test]
fn le_tampon_d_emission_grandit() {
    let mut c = etablie(true);
    c.sndbuf = 1;
    c.sndbuf_max = 1 << 30;
    c.mss = 100;
    c.mss_offre = Some(0);
    c.mss_utilisateur = 0;
    c.cc.cwnd = 1;
    c.reordering = 3;
    c.agrandir_sndbuf();
    // max(536, 100) + 640 = 1176 : 2048 + 256 = 2304 ; dix segments, deux fenêtres.
    assert_eq!(c.sndbuf, 2 * 10 * 2304);
    // TCP_MAXSEG borne l'offre.
    c.sndbuf = 1;
    c.mss_offre = Some(4000);
    c.mss_utilisateur = 1000;
    c.agrandir_sndbuf();
    // 1000 + 640 = 1640 : 2048 + 256.
    assert_eq!(c.sndbuf, 2 * 10 * 2304);
    c.sndbuf = 1;
    c.mss_utilisateur = 0;
    c.agrandir_sndbuf();
    // 4000 + 640 = 4640 : 8192 + 256.
    assert_eq!(c.sndbuf, 2 * 10 * 8448);
    // Autant de segments que le réordonnancement admis, plus un.
    c.sndbuf = 1;
    c.reordering = 20;
    c.agrandir_sndbuf();
    assert_eq!(c.sndbuf, 2 * 21 * 8448);
}

/// Le SYN compte pour un dans SND.UNA, pas dans le tampon.
#[test]
fn acquitter_le_syn_avec_les_octets() {
    let mut c = etablie(true);
    en_vol(&mut c, 2);
    c.syn_acquitte = false;
    c.snd_una -= 1;
    c.acquitter_jusqu_a(fin(0));
    assert_eq!(c.octets_envoi, MSS as usize);
    assert!(c.syn_acquitte);
}

/// `tcp_rtt_tsopt_us` : jusqu'à `INT_MAX / 1000` millisecondes.
#[test]
fn le_rtt_de_tsecr() {
    let mut c = etablie(true);
    let h = horloge_ts(HEURE);
    c.ts_recu = Some((0, h - 1000));
    assert_eq!(c.rtt_par_tsecr(HEURE, 1), Some(1000 * 1_000_000));
    c.ts_recu = Some((0, h));
    assert_eq!(c.rtt_par_tsecr(HEURE, 1), Some(1_000_000), "un écart nul : le minimum");
    assert_eq!(c.rtt_par_tsecr(HEURE, 0), Some(0));
    let tard = HEURE + 3_000_000_000_000;
    let h = horloge_ts(tard);
    let borne = i32::MAX as u32 / 1000;
    c.ts_recu = Some((0, h.wrapping_sub(borne)));
    assert_eq!(c.rtt_par_tsecr(tard, 1), None);
    c.ts_recu = Some((0, h.wrapping_sub(borne - 1)));
    assert_eq!(c.rtt_par_tsecr(tard, 1), Some((borne - 1) as u64 * 1_000_000));
    c.ts_recu = Some((0, 0));
    assert_eq!(c.rtt_par_tsecr(tard, 1), None, "sans TSecr");
}

/// `tcp_rcv_rtt_update`.
#[test]
fn le_rtt_du_recepteur() {
    let mut c = etablie(true);
    c.rcv_rtt8 = 0;
    c.rtt_reception(100, true);
    assert_eq!(c.rcv_rtt8, 800, "la première mesure");
    c.rtt_reception(99, true);
    assert_eq!(c.rcv_rtt8, 792, "plus petite : elle remplace");
    c.rcv_rtt8 = 800;
    c.rtt_reception(200, true);
    assert_eq!(c.rcv_rtt8, 800, "par fenêtre, plus grande : ignorée");
    // Par TSecr, un programme qui suit : la moyenne ; sinon, rien.
    c.rtt_reception(200, false);
    assert_eq!(c.rcv_rtt8, 800 - 100 + 200);
    c.rcv_rtt8 = 800;
    c.rcv_lu = c.rcv_nxt.wrapping_sub(1);
    c.rtt_reception(200, false);
    assert_eq!(c.rcv_rtt8, 800, "le programme est en retard");
}

/// `tcp_rcv_rtt_measure_ts` : une mesure par TSecr, d'un segment plein ; un écart nul ne compte pas.
#[test]
fn le_rtt_du_recepteur_par_tsecr() {
    let prete = || {
        let mut c = etablie(true);
        c.ack.rcv_mss = 1000;
        c.rcv_rtt8 = 0;
        c.rcv_rtt_tsecr = 0;
        c
    };
    let ecr = horloge_ts(HEURE) - 10;
    let mut c = prete();
    c.ts_recu = Some((0, ecr));
    c.rtt_reception_ts(1000, HEURE);
    assert_eq!(c.rcv_rtt8, 8 * 10 * MS);
    assert_eq!(c.rcv_rtt_tsecr, ecr);
    // Le même TSecr : rien.
    c.rcv_rtt8 = 7;
    c.rtt_reception_ts(1000, HEURE);
    assert_eq!(c.rcv_rtt8, 7);
    // Un petit segment : rien, mais la valeur est prise.
    let mut c = prete();
    c.ts_recu = Some((0, ecr));
    c.rtt_reception_ts(999, HEURE);
    assert_eq!((c.rcv_rtt8, c.rcv_rtt_tsecr), (0, ecr));
    // Sans horodatages : rien.
    let mut c = prete();
    c.rtt_reception_ts(1000, HEURE);
    assert_eq!((c.rcv_rtt8, c.rcv_rtt_tsecr), (0, 0));
    // Un écart nul : `tcp_rtt_tsopt_us(tp, 0)` rend 0 : jeté.
    let mut c = prete();
    c.rcv_rtt8 = 800;
    c.ts_recu = Some((0, horloge_ts(HEURE)));
    c.rtt_reception_ts(1000, HEURE);
    assert_eq!(c.rcv_rtt8, 800);
}

/// `tcp_init_transfer`.
#[test]
fn la_poignee_de_main_finie() {
    let prete = || {
        let mut c = etablie(true);
        c.cc.cwnd = 77;
        c.total_retrans = 2;
        c.undo_marker = Some(ISS);
        c
    };
    // Plus d'un SYN renvoyé, et pas pour rien : un seul segment.
    let mut c = prete();
    c.etablir(HEURE);
    assert_eq!(c.cc.cwnd, 1);
    // Un seul : la fenêtre de départ.
    let mut c = prete();
    c.total_retrans = 1;
    c.etablir(HEURE);
    assert_eq!(c.cc.cwnd, CWND_INITIALE);
    let mut c = prete();
    c.undo_marker = None;
    c.etablir(HEURE);
    assert_eq!(c.cc.cwnd, CWND_INITIALE);
    // Encore en perte sans SACK : elle y reste, le temps de RTO continue.
    let mut c = prete();
    c.sack_ok = false;
    c.cc.phase = Phase::Perte;
    c.rto_compter(HEURE - 5 * MS);
    let avant = c.mesures.rto_temps;
    c.etablir(HEURE);
    assert_eq!(c.cc.phase, Phase::Perte);
    assert_eq!(c.mesures.rto_temps, avant);
    assert_eq!(c.mesures.temps_de_rto(HEURE), avant + 5, "le chrono tourne encore");
    // Avec SACK : elle en sort, et le temps est compté.
    let mut c = prete();
    c.cc.phase = Phase::Perte;
    c.rto_compter(HEURE - 5 * MS);
    let avant = c.mesures.rto_temps;
    c.etablir(HEURE);
    assert_eq!(c.cc.phase, Phase::Ouverte);
    assert_eq!(c.mesures.rto_temps, avant + 5);
    // `tcp_initialize_rcv_mss` : au plus la moitié de la fenêtre.
    let mut c = prete();
    c.rcv_wnd = 300;
    c.etablir(HEURE);
    assert_eq!(c.ack.rcv_mss, 150);
    // Le keepalive, s'il est demandé.
    let mut c = prete();
    c.reglages.keepalive = true;
    c.reglages.keepidle = 5 * MS;
    c.etablir(HEURE);
    assert_eq!(c.t_keepalive, Some(HEURE + 5 * MS));
}

/// `__tcp_sock_set_nodelay`, `__tcp_sock_set_cork`, `tcp_set_keepalive`, `tcp_sock_set_keepidle_locked`.
#[test]
fn regler_() {
    let de = |avant: fn(&mut Reglages), apres: fn(&mut Reglages)| {
        let mut c = etablie(true);
        avant(&mut c.reglages);
        c.pousser = false;
        let mut r = c.reglages;
        apres(&mut r);
        let e = c.regler(r, HEURE);
        assert_eq!(e.a_emettre, c.pousser);
        e.a_emettre
    };
    assert!(de(|r| r.nodelay = false, |r| r.nodelay = true), "NODELAY posé");
    assert!(!de(|r| r.nodelay = true, |_| {}), "déjà posé");
    assert!(!de(|r| r.nodelay = true, |r| r.nodelay = false), "retiré");
    assert!(de(|r| r.cork = true, |r| r.cork = false), "CORK retiré");
    assert!(!de(|r| r.cork = false, |_| {}), "pas de CORK");
    assert!(!de(|r| r.cork = false, |r| r.cork = true), "CORK posé");
    assert!(!de(|r| r.cork = true, |_| {}), "CORK gardé");

    let vivante = || {
        let mut c = etablie(true);
        c.reglages.keepalive = false;
        c.reglages.keepidle = 100 * MS;
        c.dernier_recu = HEURE;
        c.ack.lrcvtime = HEURE;
        c
    };
    // Armé, à partir de maintenant.
    let mut c = vivante();
    let mut r = c.reglages;
    r.keepalive = true;
    c.regler(r, HEURE + 10 * MS);
    assert_eq!(c.t_keepalive, Some(HEURE + 110 * MS));
    // Déjà armé, sans rien de neuf : il reste où il est.
    c.t_keepalive = Some(1);
    c.regler(r, HEURE + 10 * MS);
    assert_eq!(c.t_keepalive, Some(1));
    // Un autre délai : recalé sur le dernier segment reçu.
    r.keepidle = 50 * MS;
    c.regler(r, HEURE + 10 * MS);
    assert_eq!(c.t_keepalive, Some(HEURE + 50 * MS));
    // Le dernier segment date de plus longtemps que le délai : tout de suite.
    r.keepidle = 5 * MS;
    c.regler(r, HEURE + 10 * MS);
    assert_eq!(c.t_keepalive, Some(HEURE + 10 * MS));
    // Retiré : plus rien. Pas encore établie, ou en TIME_WAIT : rien non plus.
    let mut c = vivante();
    let mut r = c.reglages;
    r.keepalive = true;
    c.regler(r, HEURE);
    r.keepalive = false;
    c.regler(r, HEURE);
    assert_eq!(c.t_keepalive, None);
    for etat in [Etat::Fermee, Etat::SynEnvoye, Etat::SynRecu, Etat::TempsAttente] {
        let mut c = vivante();
        c.etat = etat;
        let mut r = c.reglages;
        r.keepalive = true;
        c.regler(r, HEURE);
        assert_eq!(c.t_keepalive, None, "{etat:?}");
    }
}

/// `__tcp_sock_set_quickack`.
#[test]
fn quickack_() {
    let prete = || {
        let mut c = etablie(true);
        c.ack.programme = true;
        c.ack.pingpong = 1;
        c.ack.pousse = 0;
        c.ack.rcv_mss = 1000;
        c.rcv_wup = c.rcv_nxt;
        c.window_clamp = 1 << 16;
        c.rcv_wnd = 1 << 16;
        c.rcvbuf = 1 << 20;
        c.rcv_ssthresh = 1 << 20;
        c
    };
    // Un ACK dû part, marqué « poussé » ; une valeur impaire reste hors du ping-pong.
    let mut c = prete();
    assert!(c.quickack_valeur(1, HEURE).a_emettre);
    assert!(c.hors_du_ping_pong());
    // Une valeur paire y revient.
    let mut c = prete();
    assert!(c.quickack_valeur(2, HEURE).a_emettre);
    assert!(!c.hors_du_ping_pong());
    // Rien de dû.
    let mut c = prete();
    c.ack.programme = false;
    assert!(!c.quickack_valeur(1, HEURE).a_emettre);
    assert_eq!(c.ack.pousse, 0);
    // Ni établie, ni en CLOSE_WAIT.
    let mut c = prete();
    c.etat = Etat::FinAttente1;
    assert!(!c.quickack_valeur(1, HEURE).a_emettre);
    assert_eq!(c.ack.pousse, 0);
    let mut c = prete();
    c.etat = Etat::AttenteFermeture;
    assert!(c.quickack_valeur(1, HEURE).a_emettre);
    // 0 entre en ping-pong.
    let mut c = prete();
    c.ack.pingpong = 0;
    c.quickack_valeur(0, HEURE);
    assert!(!c.hors_du_ping_pong());
}

/// `tcp_get_info`, ce que `linux/tcp.c` ne peut pas poser.
#[test]
fn info_() {
    let mut c = etablie(true);
    c.echelle_ok = true;
    c.echelle_envoi = 3;
    c.echelle_reception = 4;
    let tard = HEURE + 5 * MS;
    c.dernier_envoi = HEURE;
    c.rcv_rtt8 = 8 * 2000;
    let i = c.info(tard);
    assert_eq!(i.dernier_envoi, 5);
    assert_eq!(i.rcv_rtt, 2);
    assert_eq!((i.echelle_envoi, i.echelle_reception), (3, 4));
    assert_eq!(i.options & 4, 4);
    assert_eq!(i.min_rtt, u32::MAX, "rien de mesuré");
    assert!(!i.sonde);
    assert!(!i.pingpong);
    assert!(i.demarrage_lent, "pas encore de seuil");
    // Pas de mesure de plus, pas d'échelle, avant d'être synchronisée.
    c.etat = Etat::SynEnvoye;
    let i = c.info(tard);
    assert_eq!((i.echelle_envoi, i.echelle_reception, i.options & 4), (0, 0, 0));
    // Synchronisée, sans échelle.
    let mut c = etablie(true);
    c.echelle_ok = false;
    c.echelle_envoi = 3;
    let i = c.info(tard);
    assert_eq!((i.echelle_envoi, i.options & 4), (0, 0));
    // Le reste.
    let mut c = etablie(true);
    c.min_rtt.mesure(1 << 40, HEURE, 7000);
    c.t_sorte = Minuteur::Sonde;
    c.ack.pingpong = 2;
    c.cc.ssthresh = 10;
    let i = c.info(tard);
    assert_eq!(i.min_rtt, 7);
    assert!(i.sonde && i.pingpong && !i.demarrage_lent);
    c.cc.ssthresh = congestion::SSTHRESH_INFINI;
    assert!(c.info(tard).demarrage_lent);
}

/// `tcp_check_urg`.
#[test]
fn le_pointeur_urgent() {
    let prete = |n: usize| {
        let mut c = etablie(true);
        if n > 0 {
            let t = ack_pur(&c);
            c.recevoir(&t, Octets((0..n).map(|i| i as u8).collect(), 0, 600 + n), HEURE);
        }
        c
    };
    // Déjà reçu, pas encore lu : ignoré. Il ne peut plus être hors du flux.
    let mut c = prete(10);
    let seq = c.rcv_lu;
    c.pointeur_urgent(5, seq);
    assert_eq!(c.urgent, Urgent::Aucun);
    // Déjà lu : ignoré.
    let mut c = prete(0);
    let seq = c.rcv_nxt.wrapping_sub(5);
    c.pointeur_urgent(1, seq);
    assert_eq!(c.urgent, Urgent::Aucun);
    // Neuf : l'octet qui précède le pointeur, à la façon de BSD.
    let mut c = prete(0);
    let seq = c.rcv_nxt;
    c.pointeur_urgent(5, seq);
    assert_eq!((c.urgent, c.urg_seq, c.urgents_annonces()), (Urgent::Attendu, seq + 4, 1));
    // Pas plus loin que celui qu'on a : ignoré ; plus loin : pris.
    c.pointeur_urgent(5, seq);
    assert_eq!(c.urgents_annonces(), 1);
    c.pointeur_urgent(4, seq);
    assert_eq!((c.urg_seq, c.urgents_annonces()), (seq + 4, 1));
    c.pointeur_urgent(6, seq);
    assert_eq!((c.urg_seq, c.urgents_annonces()), (seq + 5, 2));
    // Une vieille valeur d'`urg_seq`, sans marque : elle ne compte pas.
    let mut c = prete(0);
    let seq = c.rcv_nxt;
    c.urg_seq = seq + 100;
    c.pointeur_urgent(5, seq);
    assert_eq!((c.urgent, c.urg_seq), (Urgent::Attendu, seq + 4));
}

/// L'ancien octet urgent en tête de lecture, hors du flux : retiré quand un neuf arrive.
#[test]
fn le_pointeur_urgent_retire_l_ancien() {
    // Une marque pas encore lue, en tête, et un octet reçu.
    let prete = || {
        let mut c = etablie(true);
        let t = ack_pur(&c);
        c.recevoir(&t, Octets(vec![1, 2, 3], 0, 603), HEURE);
        c.urg_seq = c.rcv_lu;
        c.urgent = Urgent::Valide(1);
        c
    };
    let neuf = |c: &mut C| {
        let seq = c.rcv_nxt;
        c.pointeur_urgent(5, seq);
    };
    let mut c = prete();
    neuf(&mut c);
    assert_eq!(c.octets_reception, 2, "retiré");
    assert_eq!(c.rcv_lu, c.rcv_nxt - 2);
    // Sans marque : l'octet reste.
    let mut c = prete();
    c.urgent = Urgent::Aucun;
    neuf(&mut c);
    assert_eq!(c.octets_reception, 3);
    // La marque plus loin : il n'est pas en tête.
    let mut c = prete();
    c.urg_seq = c.rcv_lu + 1;
    neuf(&mut c);
    assert_eq!(c.octets_reception, 3);
    // En ligne : il fait partie du flux.
    let mut c = prete();
    c.reglages.oobinline = true;
    neuf(&mut c);
    assert_eq!(c.octets_reception, 3);
    // Rien de reçu : rien à retirer, `rcv_lu` ne bouge pas.
    let mut c = etablie(true);
    c.urg_seq = c.rcv_lu;
    c.urgent = Urgent::Attendu;
    let lu = c.rcv_lu;
    let seq = c.rcv_nxt;
    c.pointeur_urgent(5, seq);
    assert_eq!((c.rcv_lu, c.octets_reception), (lu, 0));
    assert_eq!(c.urg_seq, seq + 4);
}
