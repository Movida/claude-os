//! Une connexion TCP, de la poignée de main à la fermeture (inet::tcp) :
//! deux connexions reliées par un lien parfait (ni perte ni désordre, ce
//! que font `lo` et slirp), puis des segments faits à la main pour chaque
//! règle de la RFC 9293 et de Linux.

use formats::reseau::tcp::{self, Tcp};
use inet::tcp::{self as t, Charge, Etat, Sortant, Tcb};

/// Une charge de test : des octets, et une taille vraie au double (comme
/// un paquet du noyau).
struct Octets(Vec<u8>, usize);

impl Charge for Octets {
    fn octets(&self) -> &[u8] {
        &self.0[self.1..]
    }
    fn avancer(&mut self, n: usize) {
        self.1 = (self.1 + n).min(self.0.len());
    }
    fn taille_vraie(&self) -> usize {
        2 * self.0.len() + 64
    }
}

fn vide() -> Octets {
    Octets(Vec::new(), 0)
}

type Connexion = Tcb<Octets>;

/// Les segments que `c` a à envoyer, avec leur charge copiée.
fn sortants(c: &mut Connexion) -> Vec<(Tcp, Vec<u8>)> {
    let mut s: Vec<Sortant> = Vec::new();
    c.emettre(|x| s.push(x));
    s.into_iter()
        .map(|x| {
            let mut o = vec![0u8; x.longueur];
            c.copier_envoi(x.debut, &mut o);
            (x.entete, o)
        })
        .collect()
}

/// Livre à `b` tout ce que `a` envoie ; rend le nombre de segments.
fn livrer(a: &mut Connexion, b: &mut Connexion) -> usize {
    let s = sortants(a);
    let n = s.len();
    for (h, o) in s {
        b.recevoir(&h, Octets(o, 0));
    }
    n
}

/// Fait passer tous les segments dans les deux sens, jusqu'au calme.
fn calmer(a: &mut Connexion, b: &mut Connexion) {
    for _ in 0..10_000 {
        if livrer(a, b) + livrer(b, a) == 0 {
            return;
        }
    }
    panic!("les deux connexions ne se calment pas");
}

const MSS: u16 = 1460;

/// Une connexion établie : le client (connect) et la fille de l'écoute.
fn paire() -> (Connexion, Connexion) {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 1);
    let (syn, _) = s[0];
    assert_eq!(syn.drapeaux, tcp::SYN);
    assert_eq!(syn.options.mss, Some(MSS));
    assert_eq!(c.etat(), Etat::SynEnvoye);
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384);
    assert_eq!(f.etat(), Etat::SynRecu);
    let s = sortants(&mut f);
    assert_eq!(s[0].0.drapeaux, tcp::SYN | tcp::ACK);
    assert_eq!((s[0].0.seq, s[0].0.ack), (7000, 1001));
    c.recevoir(&s[0].0, vide());
    assert_eq!(c.etat(), Etat::Etablie);
    livrer(&mut c, &mut f);
    assert_eq!(f.etat(), Etat::Etablie);
    (c, f)
}

fn ecrire(c: &mut Connexion, o: &[u8]) -> usize {
    c.ecrire::<()>(o.len(), |d| {
        let n = d.len();
        d.copy_from_slice(&o[..n]);
        Ok(())
    })
    .unwrap()
}

fn lire(c: &mut Connexion, n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    c.lire::<()>(n, false, |m| {
        v.extend_from_slice(m);
        Ok(m.len())
    })
    .unwrap();
    c.lu();
    v
}

#[test]
fn sequences_modulo() {
    assert!(t::avant(1, 2) && t::avant(u32::MAX, 0) && t::apres(5, u32::MAX - 5) && !t::avant(3, 3));
}

#[test]
fn poignee_de_main_et_donnees() {
    let (mut c, mut f) = paire();
    assert_eq!(c.mss(), MSS);
    assert_eq!(ecrire(&mut c, b"bonjour"), 7);
    calmer(&mut c, &mut f);
    assert_eq!(f.lisibles(), 7);
    assert_eq!(lire(&mut f, 3), b"bon");
    assert_eq!(lire(&mut f, 100), b"jour");
    assert_eq!(c.non_acquittes(), 0);
    // Un gros envoi : découpé au MSS, borné par la fenêtre, tout arrive.
    let gros: Vec<u8> = (0..200_000u32).map(|i| (i * 7) as u8).collect();
    let mut recu = Vec::new();
    let mut ecrit = 0;
    for _ in 0..10_000 {
        if ecrit < gros.len() {
            ecrit += ecrire(&mut c, &gros[ecrit..]);
        }
        livrer(&mut c, &mut f);
        recu.extend(lire(&mut f, usize::MAX));
        livrer(&mut f, &mut c);
        if recu.len() == gros.len() {
            break;
        }
    }
    assert_eq!(recu, gros);
}

#[test]
fn fermeture_active_puis_time_wait() {
    let (mut c, mut f) = paire();
    c.fermer_envoi();
    assert_eq!(c.etat(), Etat::FinAttente1);
    calmer(&mut c, &mut f);
    assert_eq!(c.etat(), Etat::FinAttente2);
    assert_eq!(f.etat(), Etat::AttenteFermeture);
    assert!(f.fin_recue() && f.lisibles() == 0);
    // L'autre écrit encore, puis ferme.
    ecrire(&mut f, b"fin");
    f.fermer_envoi();
    assert_eq!(f.etat(), Etat::DernierAck);
    calmer(&mut c, &mut f);
    assert_eq!(lire(&mut c, 10), b"fin");
    assert_eq!(c.etat(), Etat::TempsAttente);
    assert_eq!(f.etat(), Etat::Fermee);
}

#[test]
fn fermeture_simultanee() {
    let (mut c, mut f) = paire();
    c.fermer_envoi();
    f.fermer_envoi();
    let a = sortants(&mut c);
    let b = sortants(&mut f);
    for (h, o) in a {
        f.recevoir(&h, Octets(o, 0));
    }
    for (h, o) in b {
        c.recevoir(&h, Octets(o, 0));
    }
    assert_eq!((c.etat(), f.etat()), (Etat::Fermeture, Etat::Fermeture));
    calmer(&mut c, &mut f);
    assert_eq!((c.etat(), f.etat()), (Etat::TempsAttente, Etat::TempsAttente));
}

#[test]
fn ouverture_simultanee() {
    let mut a = Connexion::connecter(1, 2, 100, MSS, 131_072, 16_384);
    let mut b = Connexion::connecter(2, 1, 900, MSS, 131_072, 16_384);
    let sa = sortants(&mut a);
    let sb = sortants(&mut b);
    a.recevoir(&sb[0].0, vide());
    b.recevoir(&sa[0].0, vide());
    assert_eq!((a.etat(), b.etat()), (Etat::SynRecu, Etat::SynRecu));
    calmer(&mut a, &mut b);
    assert_eq!((a.etat(), b.etat()), (Etat::Etablie, Etat::Etablie));
}

#[test]
fn refus_et_rst() {
    // Un RST qui acquitte notre SYN : ECONNREFUSED.
    let mut c = Connexion::connecter(40000, 81, 5, MSS, 131_072, 16_384);
    let syn = sortants(&mut c)[0].0;
    let rst = t::reponse_sans_connexion(&syn, 0).unwrap();
    assert_eq!((rst.drapeaux, rst.ack), (tcp::RST | tcp::ACK, 6));
    let e = c.recevoir(&rst, vide());
    assert!(e.etat && c.etat() == Etat::Fermee && c.prendre_erreur() == t::ECONNREFUSED);
    // Un RST qui n'acquitte pas notre SYN : ignoré.
    let mut c = Connexion::connecter(40000, 81, 5, MSS, 131_072, 16_384);
    sortants(&mut c);
    c.recevoir(&Tcp { drapeaux: tcp::RST, ..rst }, vide());
    assert_eq!(c.etat(), Etat::SynEnvoye);
    // Établie : un RST exactement au bord, ECONNRESET ; en CLOSE_WAIT, EPIPE.
    let (mut c, _f) = paire();
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: bord(&c), ..Tcp::default() }, vide());
    assert_eq!((c.etat(), c.prendre_erreur()), (Etat::Fermee, t::ECONNRESET));
    let (mut c, mut f) = paire();
    f.fermer_envoi();
    calmer(&mut c, &mut f);
    assert_eq!(c.etat(), Etat::AttenteFermeture);
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: bord(&c), ..Tcp::default() }, vide());
    assert_eq!(c.prendre_erreur(), t::EPIPE);
}

/// Le bord gauche de la fenêtre de `c` (le numéro qu'un RST doit avoir).
fn bord(c: &Connexion) -> u32 {
    c.numeros().2
}

#[test]
fn rst_hors_du_bord_ack_de_defi() {
    let (mut c, _f) = paire();
    let bord = bord(&c);
    // Dans la fenêtre mais pas au bord : un ACK de défi, la connexion reste.
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: bord.wrapping_add(10), ..Tcp::default() }, vide());
    assert_eq!(c.etat(), Etat::Etablie);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].0.drapeaux, tcp::ACK);
    // Hors de la fenêtre : rien.
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: bord.wrapping_add(1 << 30), ..Tcp::default() }, vide());
    assert_eq!(c.etat(), Etat::Etablie);
    assert!(sortants(&mut c).is_empty());
}

#[test]
fn avorter_envoie_rst() {
    let (mut c, mut f) = paire();
    c.avorter();
    assert_eq!(c.etat(), Etat::Fermee);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].0.drapeaux, tcp::RST | tcp::ACK);
    f.recevoir(&s[0].0, vide());
    assert_eq!((f.etat(), f.prendre_erreur()), (Etat::Fermee, t::ECONNRESET));
}

#[test]
fn segment_hors_ordre_jete_et_ack() {
    let (mut c, mut f) = paire();
    ecrire(&mut c, b"abcdef");
    let s = sortants(&mut c);
    let (h, o) = &s[0];
    // Le même segment, mais 3 octets plus loin : un trou, jeté, et l'ACK
    // redit ce qu'on attend.
    let loin = Tcp { seq: h.seq.wrapping_add(3), ..*h };
    f.recevoir(&loin, Octets(o[3..].to_vec(), 0));
    assert_eq!(f.lisibles(), 0);
    let r = sortants(&mut f);
    assert_eq!(r[0].0.ack, h.seq);
    // Puis le bon, et une copie de lui (déjà reçu : rien de plus).
    f.recevoir(h, Octets(o.clone(), 0));
    f.recevoir(h, Octets(o.clone(), 0));
    assert_eq!(lire(&mut f, 100), b"abcdef");
}

#[test]
fn fenetre_nulle_puis_ack_apres_lecture() {
    // Un récepteur de petite mémoire : la fenêtre se ferme, puis la lecture
    // la rouvre par un ACK immédiat (`lu`).
    let mut c = Connexion::connecter(1, 2, 0, MSS, 131_072, 1 << 20);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 0, MSS, 16_384, 16_384);
    calmer(&mut c, &mut f);
    let donnees = vec![7u8; 100_000];
    ecrire(&mut c, &donnees);
    calmer(&mut c, &mut f);
    let lus = f.lisibles();
    assert!(lus > 0 && lus < 100_000, "{}", lus);
    assert!(c.non_envoyes() > 0);
    // Rien ne bouge sans lecture.
    assert_eq!(livrer(&mut c, &mut f), 0);
    // Lire : un ACK part, et l'émetteur reprend.
    lire(&mut f, usize::MAX);
    assert!(livrer(&mut f, &mut c) >= 1);
    assert!(livrer(&mut c, &mut f) >= 1);
    let mut total = lus;
    for _ in 0..1000 {
        let n = lire(&mut f, usize::MAX).len();
        total += n;
        calmer(&mut c, &mut f);
        if total == 100_000 {
            break;
        }
    }
    total += lire(&mut f, usize::MAX).len();
    assert_eq!(total, 100_000);
}

#[test]
fn erreurs_icmp() {
    // Pendant la poignée de main, toute erreur ferme la connexion (même
    // « hôte injoignable », qu'icmp_err_convert ne dit pas fatale).
    let mut c = Connexion::connecter(1, 2, 0, MSS, 131_072, 16_384);
    sortants(&mut c);
    c.erreur_icmp(113, false, false);
    assert_eq!((c.etat(), c.prendre_erreur()), (Etat::Fermee, 113));
    // Établie : douce, sauf avec IP_RECVERR.
    let (mut c, _) = paire();
    c.erreur_icmp(113, true, false);
    assert_eq!((c.etat(), c.erreur(), c.erreur_douce()), (Etat::Etablie, 0, 113));
    c.erreur_icmp(113, false, true);
    assert_eq!(c.prendre_erreur(), 113);
}

#[test]
fn sans_connexion() {
    // Un RST ne reçoit rien ; un ACK, un RST de ce numéro ; sinon RST+ACK
    // de tout ce que portait le segment.
    let h = Tcp { source: 5, destination: 6, seq: 100, ack: 200, ..Tcp::default() };
    assert_eq!(t::reponse_sans_connexion(&Tcp { drapeaux: tcp::RST, ..h }, 0), None);
    let r = t::reponse_sans_connexion(&Tcp { drapeaux: tcp::ACK, ..h }, 9).unwrap();
    assert_eq!((r.source, r.destination, r.seq, r.drapeaux), (6, 5, 200, tcp::RST));
    let r = t::reponse_sans_connexion(&Tcp { drapeaux: tcp::SYN | tcp::FIN, ..h }, 9).unwrap();
    assert_eq!((r.ack, r.drapeaux), (111, tcp::RST | tcp::ACK));
}

/// Le MSS d'envoi : une offre de 0 est ignorée (536), une offre de 1 donne
/// 48 (`tcp_min_snd_mss`), jamais des segments d'un octet.
#[test]
fn mss_du_pair_borne() {
    for (offre, attendu) in [(0u16, 536usize), (1, 48)] {
        let mut c = Connexion::connecter(40000, 80, 1000, offre, 131_072, 16_384);
        let syn = sortants(&mut c)[0].0;
        let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384);
        calmer(&mut c, &mut f);
        ecrire(&mut f, &[5u8; 1000]);
        let s = sortants(&mut f);
        assert_eq!(s.iter().map(|(_, o)| o.len()).max(), Some(attendu), "offre {offre}");
    }
}

/// Une connexion que le programme a fermée (`close` : la lecture aussi),
/// en FIN_WAIT_1 : des données neuves de l'autre la coupent, RST (RFC
/// 1122 4.2.2.13, `tcp_rcv_state_process`) ; l'autre voit ECONNRESET.
#[test]
fn donnees_apres_close_en_fin_wait() {
    let (mut c, mut f) = paire();
    c.fermer_lecture();
    c.fermer_envoi();
    assert_eq!(c.etat(), Etat::FinAttente1);
    let fin = sortants(&mut c);
    assert_eq!(fin.len(), 1);
    ecrire(&mut f, b"y");
    let s = sortants(&mut f);
    for (h, o) in s {
        c.recevoir(&h, Octets(o, 0));
    }
    assert_eq!(c.etat(), Etat::Fermee);
    let r = sortants(&mut c);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0.drapeaux & tcp::RST, tcp::RST);
    f.recevoir(&r[0].0, vide());
    assert_eq!((f.etat(), f.prendre_erreur()), (Etat::Fermee, t::ECONNRESET));
}

/// Une copie qui échoue après des octets déjà pris rend ce qui a été lu
/// (`tcp_recvmsg_locked`), et laisse le reste en file.
#[test]
fn copie_qui_faute_rend_ce_qui_est_lu() {
    let (mut c, mut f) = paire();
    ecrire(&mut c, b"abc");
    livrer(&mut c, &mut f);
    ecrire(&mut c, b"def");
    calmer(&mut c, &mut f);
    let mut morceaux = 0;
    let n = f.lire::<i32>(100, false, |m| {
        morceaux += 1;
        if morceaux == 2 { Err(14) } else { Ok(m.len()) }
    });
    assert_eq!(n, Ok(3));
    assert_eq!(f.lisibles(), 3);
    let mut seul = 0;
    assert_eq!(f.lire::<i32>(100, false, |_| { seul += 1; Err(14) }), Err(14));
    assert_eq!((seul, f.lisibles()), (1, 3));
}

/// L'ACK qui couvre les données mais pas le FIN : FIN_WAIT_1 reste.
#[test]
fn ack_des_donnees_sans_le_fin() {
    let (mut c, _f) = paire();
    ecrire(&mut c, b"abc");
    c.fermer_envoi();
    let s = sortants(&mut c);
    let fin = s.iter().find(|(h, _)| h.drapeaux & tcp::FIN != 0).expect("le FIN");
    let fin_seq = fin.0.seq.wrapping_add(fin.1.len() as u32);
    c.recevoir(&Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: fin_seq, fenetre: 65_535, ..Tcp::default() }, vide());
    assert_eq!(c.etat(), Etat::FinAttente1);
    c.recevoir(&Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: fin_seq.wrapping_add(1), fenetre: 65_535, ..Tcp::default() }, vide());
    assert_eq!(c.etat(), Etat::FinAttente2);
}

/// Le récepteur n'ouvre pas sa fenêtre par petits morceaux (RFC 9293
/// 3.8.6.2.2, le syndrome de la fenêtre stupide) : tant que la place rendue
/// ne fait ni un MSS ni le quart de SO_RCVBUF, la fenêtre ne s'ouvre pas ;
/// ensuite, si.
#[test]
fn pas_de_petite_fenetre() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 65_536);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 16_384, 16_384);
    calmer(&mut c, &mut f);
    // La fenêtre de départ, la moitié de SO_RCVBUF : 8192 octets, envoyés
    // tous. Elle est alors presque fermée (pas toujours tout à fait : son
    // bord n'est jamais reculé, et peut être arrondi, `tcp_select_window`).
    assert_eq!(f.fenetre_annoncee(), 8192);
    ecrire(&mut c, &[1u8; 8192]);
    calmer(&mut c, &mut f);
    let w0 = f.fenetre_annoncee();
    assert!(w0 < 512, "{w0}");
    lire(&mut f, MSS as usize);
    sortants(&mut f);
    assert_eq!(f.fenetre_annoncee(), w0, "un segment lu : la place rendue ne fait pas un MSS");
    lire(&mut f, 2 * MSS as usize);
    sortants(&mut f);
    assert!(f.fenetre_annoncee() >= MSS as u32, "{}", f.fenetre_annoncee());
}
