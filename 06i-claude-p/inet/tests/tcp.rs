//! Une connexion TCP, de la poignée de main à la fermeture (inet::tcp) :
//! deux connexions reliées par un lien parfait (ni perte ni désordre, ce
//! que font `lo` et slirp), puis des segments faits à la main pour chaque
//! règle de la RFC 9293 et de Linux.

use formats::reseau::tcp::{self, Tcp};
use inet::tcp::{self as t, Charge, Etat, Sortant, Tcb};
use std::cell::Cell;

// L'horloge des tests, en nanosecondes : elle n'avance que quand un test
// le demande (`avancer`), ou quand `calmer` laisse partir un ACK retardé. Elle ne part pas de 0 :
// pour la connexion, 0 veut dire « aucune heure » (`retrans_stamp`).
thread_local! {
    static HEURE: Cell<u64> = const { Cell::new(7_000_000_000) };
}

fn maintenant() -> u64 {
    HEURE.with(|h| h.get())
}

fn avancer(ns: u64) {
    HEURE.with(|h| h.set(h.get() + ns));
}

const MS: u64 = 1_000_000;

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
    fn neuve(n: usize) -> Option<Octets> {
        Some(Octets(Vec::with_capacity(n), 0))
    }
    fn completer(&mut self, o: &[u8]) {
        self.0.extend_from_slice(o);
    }
}

fn vide() -> Octets {
    Octets(Vec::new(), 0)
}

type Connexion = Tcb<Octets>;

/// Les segments que `c` a à envoyer, avec leur charge copiée.
fn sortants(c: &mut Connexion) -> Vec<(Tcp, Vec<u8>)> {
    let mut s: Vec<Sortant> = Vec::new();
    c.emettre(maintenant(), |x| s.push(x));
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
        b.recevoir(&h, Octets(o, 0), maintenant());
    }
    n
}

/// Fait passer tous les segments dans les deux sens, jusqu'au calme ; les
/// ACK retardés (une échéance à moins de 100 ms) partent en route, l'heure
/// avançant jusqu'à eux. Les retransmissions et les sondes (200 ms au
/// moins) ne sont pas touchées.
fn calmer(a: &mut Connexion, b: &mut Connexion) {
    for _ in 0..100_000 {
        if livrer(a, b) + livrer(b, a) > 0 {
            continue;
        }
        match [a.echeance(), b.echeance()].into_iter().flatten().min() {
            Some(e) if e <= maintenant() + 100 * MS => {
                avancer(e.saturating_sub(maintenant()));
                a.minuteur(maintenant());
                b.minuteur(maintenant());
            }
            _ => return,
        }
    }
    panic!("les deux connexions ne se calment pas");
}

const MSS: u16 = 1460;
/// Le seuil d'avant toute perte (TCP_INFINITE_SSTHRESH).
const SEUIL_INFINI: u32 = 0x7fff_ffff;
/// L'échelle de fenêtre que proposent les connexions de ces tests : celle
/// d'une machine où `tcp_rmem[2]` vaut 6 Mio (ilog2(6 Mio) - 15 ; voir
/// `echelle_comme_linux`).
const ECHELLE: u8 = 7;

/// Une connexion établie : le client (connect) et la fille de l'écoute.
fn paire() -> (Connexion, Connexion) {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 1);
    let (syn, _) = s[0];
    assert_eq!(syn.drapeaux, tcp::SYN);
    assert_eq!(syn.options.mss, Some(MSS));
    assert_eq!(c.etat(), Etat::SynEnvoye);
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    assert_eq!(f.etat(), Etat::SynRecu);
    let s = sortants(&mut f);
    assert_eq!(s[0].0.drapeaux, tcp::SYN | tcp::ACK);
    assert_eq!((s[0].0.seq, s[0].0.ack), (7000, 1001));
    c.recevoir(&s[0].0, vide(), maintenant());
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
    c.lu(v.len(), maintenant());
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
        // (Le dernier petit segment attend l'ACK du précédent : Nagle.)
        calmer(&mut c, &mut f);
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
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    for (h, o) in b {
        c.recevoir(&h, Octets(o, 0), maintenant());
    }
    assert_eq!((c.etat(), f.etat()), (Etat::Fermeture, Etat::Fermeture));
    calmer(&mut c, &mut f);
    assert_eq!((c.etat(), f.etat()), (Etat::TempsAttente, Etat::TempsAttente));
}

#[test]
fn ouverture_simultanee() {
    let mut a = Connexion::connecter(1, 2, 100, MSS, 131_072, 16_384, ECHELLE);
    let mut b = Connexion::connecter(2, 1, 900, MSS, 131_072, 16_384, ECHELLE);
    let sa = sortants(&mut a);
    let sb = sortants(&mut b);
    a.recevoir(&sb[0].0, vide(), maintenant());
    b.recevoir(&sa[0].0, vide(), maintenant());
    assert_eq!((a.etat(), b.etat()), (Etat::SynRecu, Etat::SynRecu));
    calmer(&mut a, &mut b);
    assert_eq!((a.etat(), b.etat()), (Etat::Etablie, Etat::Etablie));
}

#[test]
fn refus_et_rst() {
    // Un RST qui acquitte notre SYN : ECONNREFUSED.
    let mut c = Connexion::connecter(40000, 81, 5, MSS, 131_072, 16_384, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let rst = t::reponse_sans_connexion(&syn, 0).unwrap();
    assert_eq!((rst.drapeaux, rst.ack), (tcp::RST | tcp::ACK, 6));
    let e = c.recevoir(&rst, vide(), maintenant());
    assert!(e.etat && c.etat() == Etat::Fermee && c.prendre_erreur() == t::ECONNREFUSED);
    // Un RST qui n'acquitte pas notre SYN : ignoré.
    let mut c = Connexion::connecter(40000, 81, 5, MSS, 131_072, 16_384, ECHELLE);
    sortants(&mut c);
    c.recevoir(&Tcp { drapeaux: tcp::RST, ..rst }, vide(), maintenant());
    assert_eq!(c.etat(), Etat::SynEnvoye);
    // Établie : un RST exactement au bord, ECONNRESET ; en CLOSE_WAIT, EPIPE.
    let (mut c, _f) = paire();
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: bord(&c), ..Tcp::default() }, vide(), maintenant());
    assert_eq!((c.etat(), c.prendre_erreur()), (Etat::Fermee, t::ECONNRESET));
    let (mut c, mut f) = paire();
    f.fermer_envoi();
    calmer(&mut c, &mut f);
    assert_eq!(c.etat(), Etat::AttenteFermeture);
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: bord(&c), ..Tcp::default() }, vide(), maintenant());
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
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: bord.wrapping_add(10), ..Tcp::default() }, vide(), maintenant());
    assert_eq!(c.etat(), Etat::Etablie);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].0.drapeaux, tcp::ACK);
    // Hors de la fenêtre : rien.
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: bord.wrapping_add(1 << 30), ..Tcp::default() }, vide(), maintenant());
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
    f.recevoir(&s[0].0, vide(), maintenant());
    assert_eq!((f.etat(), f.prendre_erreur()), (Etat::Fermee, t::ECONNRESET));
}

#[test]
fn segment_hors_ordre_garde_et_ack_duplique() {
    let (mut c, mut f) = paire();
    ecrire(&mut c, b"abcdef");
    let s = sortants(&mut c);
    let (h, o) = &s[0];
    // La fin du segment seule, 3 octets plus loin : un trou devant ; elle
    // est gardée (rien à lire encore), et l'ACK part tout de suite, qui
    // redit ce qu'on attend.
    let loin = Tcp { seq: h.seq.wrapping_add(3), ..*h };
    f.recevoir(&loin, Octets(o[3..].to_vec(), 0), maintenant());
    assert_eq!(f.lisibles(), 0);
    let r = sortants(&mut f);
    assert_eq!((r.len(), r[0].0.ack), (1, h.seq));
    // Puis le segment entier : le trou se comble, la fin gardée est jetée
    // (déjà là), et une copie du segment n'ajoute rien.
    f.recevoir(h, Octets(o.clone(), 0), maintenant());
    f.recevoir(h, Octets(o.clone(), 0), maintenant());
    assert_eq!(lire(&mut f, 100), b"abcdef");
}

#[test]
fn fenetre_nulle_puis_ack_apres_lecture() {
    // Un récepteur de petite mémoire : la fenêtre se ferme, puis la lecture
    // la rouvre par un ACK immédiat (`lu`).
    let mut c = Connexion::connecter(1, 2, 0, MSS, 131_072, 1 << 20, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 0, MSS, 16_384, 16_384, ECHELLE);
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
    let mut c = Connexion::connecter(1, 2, 0, MSS, 131_072, 16_384, ECHELLE);
    sortants(&mut c);
    c.erreur_icmp(113, 0, true, false, maintenant());
    assert_eq!((c.etat(), c.prendre_erreur()), (Etat::Fermee, 113));
    // Établie : douce, sauf avec IP_RECVERR.
    let (mut c, _) = paire();
    let una = c.numeros().0;
    c.erreur_icmp(113, una, true, false, maintenant());
    assert_eq!((c.etat(), c.erreur(), c.erreur_douce()), (Etat::Etablie, 0, 113));
    c.erreur_icmp(113, una, true, true, maintenant());
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
        let mut c = Connexion::connecter(40000, 80, 1000, offre, 131_072, 16_384, ECHELLE);
        let syn = sortants(&mut c)[0].0;
        let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
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
        c.recevoir(&h, Octets(o, 0), maintenant());
    }
    assert_eq!(c.etat(), Etat::Fermee);
    let r = sortants(&mut c);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0.drapeaux & tcp::RST, tcp::RST);
    f.recevoir(&r[0].0, vide(), maintenant());
    assert_eq!((f.etat(), f.prendre_erreur()), (Etat::Fermee, t::ECONNRESET));
}

/// Une copie qui échoue après des octets déjà pris rend ce qui a été lu
/// (`tcp_recvmsg_locked`), et laisse le reste en file.
#[test]
fn copie_qui_faute_rend_ce_qui_est_lu() {
    let (mut c, mut f) = paire();
    let r = t::Reglages { nodelay: true, ..c.reglages };
    c.regler(r, maintenant());
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
    c.recevoir(&Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: fin_seq, fenetre: 65_535, ..Tcp::default() }, vide(), maintenant());
    assert_eq!(c.etat(), Etat::FinAttente1);
    c.recevoir(&Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: fin_seq.wrapping_add(1), fenetre: 65_535, ..Tcp::default() }, vide(),
               maintenant());
    assert_eq!(c.etat(), Etat::FinAttente2);
}

/// Le récepteur n'ouvre pas sa fenêtre par petits morceaux (RFC 9293
/// 3.8.6.2.2, le syndrome de la fenêtre stupide) : tant que la place rendue
/// ne fait pas un MSS, la fenêtre ne s'ouvre pas ; ensuite, si.
#[test]
fn pas_de_petite_fenetre() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 65_536, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 16_384, 16_384, ECHELLE);
    calmer(&mut c, &mut f);
    // La fenêtre de départ, la moitié de SO_RCVBUF arrondie au MSS : 7300 octets,
    // envoyés tous. Elle est alors fermée.
    assert_eq!(f.fenetre_annoncee(), 7300);
    ecrire(&mut c, &[1u8; 7300]);
    calmer(&mut c, &mut f);
    let w0 = f.fenetre_annoncee();
    assert!(w0 < 512, "{w0}");
    // Un peu lu : aucune mémoire rendue, rien.
    lire(&mut f, 100);
    sortants(&mut f);
    assert_eq!(f.fenetre_annoncee(), w0, "la place rendue ne fait pas un MSS");
    lire(&mut f, 2 * MSS as usize);
    sortants(&mut f);
    assert!(f.fenetre_annoncee() >= MSS as u32, "{}", f.fenetre_annoncee());
}

// --- La fiabilité (6h, commit 6) ---

/// Fait passer l'heure jusqu'à la prochaine échéance de `c`, et la traite.
fn echeance_suivante(c: &mut Connexion) {
    let e = c.echeance().expect("une échéance");
    avancer(e.saturating_sub(maintenant()));
    c.minuteur(maintenant());
}

/// Les heures (en ms, depuis le `connect`) des SYN d'une connexion à qui
/// personne ne répond, celle de son abandon, et son erreur.
fn syn_sans_reponse(syncnt: u32) -> (Vec<u64>, u64, i32) {
    let debut = maintenant();
    let mut c = Connexion::connecter(1, 2, 0, MSS, 131_072, 16_384, ECHELLE);
    c.reglages.syn_essais = syncnt;
    let mut syn = Vec::new();
    loop {
        for (h, _) in sortants(&mut c) {
            assert_eq!(h.drapeaux, tcp::SYN);
            syn.push((maintenant() - debut) / MS);
        }
        if c.etat() == Etat::Fermee {
            return (syn, (maintenant() - debut) / MS, c.prendre_erreur());
        }
        echeance_suivante(&mut c);
    }
}

#[test]
fn syn_sans_reponse_comme_linux() {
    // Mesuré sur Linux 6.18 (le « trou noir » de lo) : TCP_SYNCNT 1, trois
    // SYN et ETIMEDOUT en 3 s ; TCP_SYNCNT 2, six SYN et 7 s. Les quatre
    // premières retransmissions ne doublent pas le RTO.
    assert_eq!(syn_sans_reponse(1), (vec![0, 1000, 2000], 3000, t::ETIMEDOUT));
    assert_eq!(syn_sans_reponse(2), (vec![0, 1000, 2000, 3000, 4000, 5000], 7000, t::ETIMEDOUT));
    // Par défaut (6) : onze SYN, 131 s.
    let (syn, fin, e) = syn_sans_reponse(0);
    assert_eq!(syn, vec![0, 1000, 2000, 3000, 4000, 5000, 7000, 11_000, 19_000, 35_000, 67_000]);
    assert_eq!((fin, e), (131_000, t::ETIMEDOUT));
}

#[test]
fn syn_ack_sans_reponse() {
    // La fille d'une écoute : cinq retransmissions du SYN-ACK
    // (`tcp_synack_retries`), le RTO doublé chaque fois, puis elle s'en va.
    let syn = Tcp { source: 2, destination: 1, seq: 500, drapeaux: tcp::SYN, fenetre: 65_535, ..Tcp::default() };
    let debut = maintenant();
    let mut f = Connexion::depuis_syn(&syn, 0, MSS, 131_072, 16_384, ECHELLE);
    let mut heures = Vec::new();
    while f.etat() != Etat::Fermee {
        for (h, _) in sortants(&mut f) {
            assert_eq!(h.drapeaux, tcp::SYN | tcp::ACK);
            heures.push((maintenant() - debut) / MS);
        }
        if f.etat() != Etat::Fermee {
            echeance_suivante(&mut f);
        }
    }
    assert_eq!(heures, vec![0, 1000, 3000, 7000, 15_000, 31_000]);
    assert_eq!((maintenant() - debut) / MS, 63_000);
}

#[test]
fn retransmission_par_le_rto_et_karn() {
    let (mut c, mut f) = paire();
    // Après la poignée de main (un RTT mesuré de presque rien), le RTO vaut
    // son plancher : 200 ms.
    assert_eq!(c.congestion().2 / MS, 200);
    ecrire(&mut c, b"perdu");
    assert_eq!(sortants(&mut c).len(), 1);
    let t0 = maintenant();
    echeance_suivante(&mut c);
    assert_eq!((maintenant() - t0) / MS, 200);
    let s = sortants(&mut c);
    assert_eq!((s.len(), &s[0].1[..]), (1, &b"perdu"[..]));
    // Doublé ; la fenêtre de congestion à un segment.
    assert_eq!((c.congestion().0, c.congestion().2 / MS), (1, 400));
    // La copie arrive et son ACK revient : pas de mesure (Karn), le RTO
    // reste doublé.
    for (h, o) in s {
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    calmer(&mut c, &mut f);
    assert_eq!(lire(&mut f, 100), b"perdu");
    assert_eq!(c.congestion().2 / MS, 400);
    // Un segment neuf, acquitté : une mesure, et le RTO revient.
    ecrire(&mut c, b"neuf");
    calmer(&mut c, &mut f);
    assert_eq!(c.congestion().2 / MS, 200);
}

/// Dix segments pleins de `c`, dont ceux de `perdus` (leurs rangs) se
/// perdent ; les autres arrivent dans l'ordre. Rend les segments.
fn dix_segments(c: &mut Connexion) -> Vec<(Tcp, Vec<u8>)> {
    let donnees: Vec<u8> = (0..10 * MSS as usize).map(|i| (i % 251) as u8).collect();
    assert_eq!(ecrire(c, &donnees), donnees.len());
    let s = sortants(c);
    // La fenêtre de congestion de départ : dix segments (RFC 6928).
    assert_eq!(s.len(), 10);
    s
}

/// Livre à `f` les segments `s` sauf ceux de rang `perdus`, et à `c` ce que
/// `f` répond, segment par segment ; rend ce que `c` renvoie.
fn livrer_sauf(c: &mut Connexion, f: &mut Connexion, s: Vec<(Tcp, Vec<u8>)>, perdus: &[usize]) -> Vec<(Tcp, Vec<u8>)> {
    let mut renvoyes = Vec::new();
    for (i, (h, o)) in s.into_iter().enumerate() {
        if perdus.contains(&i) {
            continue;
        }
        f.recevoir(&h, Octets(o, 0), maintenant());
        for (r, _) in sortants(f) {
            c.recevoir(&r, vide(), maintenant());
            renvoyes.extend(sortants(c));
        }
    }
    renvoyes
}

#[test]
fn retransmission_rapide_au_troisieme_ack_duplique() {
    let (mut c, mut f) = paire();
    let s = dix_segments(&mut c);
    let tete = s[0].0.seq;
    // Le premier se perd : chacun des neuf autres fait un ACK dupliqué ; au
    // troisième, la tête repart, sans attendre le RTO (l'heure n'a pas
    // bougé), et elle seule.
    let renvoyes = livrer_sauf(&mut c, &mut f, s, &[0]);
    assert_eq!(renvoyes.len(), 1);
    assert_eq!((renvoyes[0].0.seq, renvoyes[0].1.len()), (tete, MSS as usize));
    // Elle arrive : le trou se comble, l'ACK couvre tout ; la reprise
    // s'achève, la fenêtre de congestion au seuil : pour CUBIC, 70 % de dix.
    let fin = livrer_sauf(&mut c, &mut f, renvoyes, &[]);
    assert!(fin.is_empty());
    assert_eq!(f.lisibles(), 10 * MSS as usize);
    assert_eq!((c.congestion().0, c.congestion().1), (7, 7));
    assert_eq!(c.non_acquittes(), 0);
}

/// La même perte, avec Reno : la moitié (TCP_CONGESTION « reno »).
#[test]
fn reno_reduit_de_moitie() {
    let (mut c, mut f) = paire();
    assert_eq!(c.controle(), t::Controle::Cubic);
    c.choisir_controle(t::Controle::Reno, maintenant());
    assert_eq!(c.controle(), t::Controle::Reno);
    let s = dix_segments(&mut c);
    let renvoyes = livrer_sauf(&mut c, &mut f, s, &[0]);
    assert!(livrer_sauf(&mut c, &mut f, renvoyes, &[]).is_empty());
    assert_eq!((c.congestion().0, c.congestion().1), (5, 5));
}

/// Les noms des contrôles (`tcp_ca_find`), et celui d'une socket neuve.
#[test]
fn noms_des_controles() {
    use t::Controle;
    assert_eq!((Controle::par_nom(b"cubic"), Controle::par_nom(b"reno")), (Some(Controle::Cubic), Some(Controle::Reno)));
    assert_eq!((Controle::par_nom(b""), Controle::par_nom(b"bbr"), Controle::par_nom(b"cubi")), (None, None, None));
    assert_eq!((Controle::DEFAUT, Controle::Cubic.nom(), Controle::Reno.nom()), (Controle::Cubic, &b"cubic"[..], &b"reno"[..]));
}

/// La cwnd portée à `n` segments au moins, par Reno (l'heure n'avançant que pour
/// les ACK retardés, HyStart n'y verrait rien).
fn grandir(c: &mut Connexion, f: &mut Connexion, n: u32) {
    for _ in 0..30 {
        if c.congestion().0 >= n {
            return;
        }
        let cwnd = c.congestion().0 as usize;
        ecrire(c, &vec![0u8; cwnd * MSS as usize]);
        calmer(c, f);
        let _ = lire(f, 1 << 30);
    }
    panic!("la cwnd ne grandit pas : {}", c.congestion().0);
}

/// Le débit calculé (`tcp_update_pacing_rate`) : cwnd × MSS / SRTT, à 200 % en
/// démarrage lent, à 120 % ensuite. L'infini avant toute mesure ; puis dès le
/// premier ACK du client, et l'établissement de la fille (`tcp_rcv_state_process`).
#[test]
fn debit_calcule() {
    let mss = MSS as u64;
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 1 << 24, 1 << 24, ECHELLE);
    assert_eq!(c.info(maintenant()).pacing, t::PACING_MAX);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 1 << 24, 1 << 24, ECHELLE);
    let synack = sortants(&mut f)[0].0;
    avancer(10 * MS);
    c.recevoir(&synack, vide(), maintenant());
    // 1460 × 10 segments / 10 ms = 1,46 Mo/s, à 200 %.
    assert_eq!(c.info(maintenant()).pacing, 2_920_000);
    let ack = sortants(&mut c)[0].0;
    avancer(10 * MS);
    f.recevoir(&ack, vide(), maintenant());
    // La fille a vu 20 ms.
    assert_eq!(f.info(maintenant()).pacing, 2 * mss * 10 * 1000 / 20);
    // Un ACK de données, après 10 ms (la mesure ne change pas SRTT). Démarrage
    // lent : 200 %. (La cwnd ne grandit pas : ces deux segments ne la remplissaient
    // pas.)
    ecrire(&mut c, &vec![0u8; 2 * MSS as usize]);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 2);
    for (h, o) in s {
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    let acks = sortants(&mut f);
    avancer(10 * MS);
    for (h, _) in acks {
        c.recevoir(&h, vide(), maintenant());
    }
    let i = c.info(maintenant());
    assert_eq!((i.rtt, i.cwnd), (10_000, 10));
    assert_eq!(i.pacing, 2 * mss * 10 * 1000 / 10);
    // Passé le seuil : 120 %.
    let _ = lire(&mut f, 1 << 30);
    let s = dix_segments(&mut c);
    let renvoyes = livrer_sauf(&mut c, &mut f, s, &[0]);
    assert!(livrer_sauf(&mut c, &mut f, renvoyes, &[]).is_empty());
    let i = c.info(maintenant());
    assert!(i.cwnd >= i.ssthresh && i.ssthresh < 12, "cwnd {}, seuil {}", i.cwnd, i.ssthresh);
    assert_eq!(i.pacing, mss * 12 * i.cwnd as u64 * 100 / 10);
}

/// Une salve de `cwnd` segments, un RTT de 10 ms, et des ACK qui reviennent à 1 ms
/// d'intervalle, comme à travers un goulet : le train d'ACK de HyStart. Rend
/// (cwnd, seuil).
fn tour_en_train(c: &mut Connexion, f: &mut Connexion) -> (u32, u32) {
    let s = sortants(c);
    avancer(5 * MS);
    let mut acks = Vec::new();
    for (h, o) in s {
        f.recevoir(&h, Octets(o, 0), maintenant());
        acks.extend(sortants(f));
        let _ = lire(f, 1 << 30);
    }
    avancer(5 * MS);
    for (h, _) in acks {
        c.recevoir(&h, vide(), maintenant());
        avancer(MS);
    }
    (c.congestion().0, c.congestion().1)
}

/// HyStart (CUBIC) : le train d'ACK dure plus d'un demi-RTT, le démarrage lent
/// s'arrête là : le seuil devient la cwnd, sans aucune perte. Reno, lui, continue
/// jusqu'à la perte.
#[test]
fn hystart_sort_du_demarrage_lent_sans_perte() {
    let (mut c, mut f) = paire_avec(MSS, 1 << 25, 1 << 25);
    ecrire(&mut c, &vec![0u8; 1 << 24]);
    let mut seuil = SEUIL_INFINI;
    for _ in 0..10 {
        (_, seuil) = tour_en_train(&mut c, &mut f);
    }
    assert!((16..200).contains(&seuil), "seuil {seuil}");
    assert!(c.congestion().0 < 2 * seuil, "la cwnd ne double plus : {} pour un seuil de {seuil}", c.congestion().0);
    assert_eq!(c.info(maintenant()).total_rto, 0);

    let (mut c, mut f) = paire_avec(MSS, 1 << 25, 1 << 25);
    c.choisir_controle(t::Controle::Reno, maintenant());
    ecrire(&mut c, &vec![0u8; 1 << 24]);
    for _ in 0..10 {
        (_, seuil) = tour_en_train(&mut c, &mut f);
    }
    assert_eq!(seuil, SEUIL_INFINI);
    assert!(c.congestion().0 > 400);
}

/// `tcp_cwnd_application_limited` (RFC 2861) : la cwnd ne sert plus depuis un RTO
/// (le dernier ACK date, et il reste du vol) : elle redescend à mi-chemin de ce qui
/// a servi, 10 segments au moins ; le seuil en garde les trois quarts. Pas si le
/// programme attend de la place : il n'est pas à court de quoi envoyer.
#[test]
fn cwnd_relachee_quand_le_programme_ne_la_remplit_pas() {
    let essai = |bloque: bool| {
        let (mut c, mut f) = paire_avec(MSS, 1 << 24, 1 << 24);
        c.choisir_controle(t::Controle::Reno, maintenant());
        grandir(&mut c, &mut f, 30);
        let cwnd = c.congestion().0;
        if bloque {
            c.marquer_sans_place();
        }
        let rto = c.congestion().2;
        let r = t::Reglages { nodelay: true, ..c.reglages };
        c.regler(r, maintenant());
        // Le premier petit envoi, moins d'un RTO après le dernier ACK : rien ne
        // bouge encore.
        avancer(rto * 3 / 4);
        ecrire(&mut c, b"a");
        assert_eq!(sortants(&mut c).len(), 1);
        assert_eq!(c.congestion().0, cwnd);
        // Le second, un RTO passé, le premier encore en vol.
        avancer(rto / 2);
        ecrire(&mut c, b"b");
        assert_eq!(sortants(&mut c).len(), 1);
        (cwnd, c.congestion().0, c.congestion().1)
    };
    let (cwnd, apres, seuil) = essai(false);
    assert_eq!(apres, (cwnd + 10) / 2);
    assert_eq!(seuil, SEUIL_INFINI, "le seuil ne baisse pas : sa valeur infinie reste la plus grande");
    let (cwnd, apres, _) = essai(true);
    assert_eq!(apres, cwnd, "un programme qui attend de la place ne relâche rien");
}

/// `tcp_cwnd_restart` (RFC 2861), après un silence, rien en vol : la moitié par
/// RTO écoulé, sans passer sous la fenêtre de départ, et le temps du silence ne
/// compte pas pour la courbe de CUBIC.
#[test]
fn cwnd_apres_un_long_silence() {
    let (mut c, mut f) = paire_avec(MSS, 1 << 24, 1 << 24);
    c.choisir_controle(t::Controle::Reno, maintenant());
    grandir(&mut c, &mut f, 30);
    calmer(&mut c, &mut f);
    let cwnd = c.congestion().0;
    avancer(c.congestion().2 * 3 / 2);
    ecrire(&mut c, b"a");
    assert_eq!(sortants(&mut c).len(), 1);
    assert_eq!(c.congestion().0, cwnd / 2);
    // Un FIN seul ne redémarre pas la cwnd (`tcp_send_fin` n'y passe pas : elle
    // aurait été divisée par deux à chaque RTO) ; il la relâche (il est sorti, et
    // la cwnd n'a pas servi depuis plus d'un RTO).
    let (mut c, mut f) = paire_avec(MSS, 1 << 24, 1 << 24);
    grandir(&mut c, &mut f, 30);
    calmer(&mut c, &mut f);
    let cwnd = c.congestion().0;
    avancer(c.congestion().2 * 3);
    c.fermer_envoi();
    assert_eq!(sortants(&mut c).len(), 1);
    assert_eq!(c.congestion().0, (cwnd + 10) / 2);
}

/// SO_SNDBUF ne suit la cwnd que pour un programme qui attend de la place
/// (`tcp_check_space`, SOCK_NOSPACE) : deux fenêtres de congestion, à l'envoi
/// d'un segment neuf, ou à un segment reçu, si la cwnd n'est pas pleine.
#[test]
fn sndbuf_suit_la_cwnd_si_le_programme_attend() {
    let (mut c, mut f) = paire_avec(MSS, 1 << 24, 87_040);
    let depart = c.sndbuf;
    c.choisir_controle(t::Controle::Reno, maintenant());
    // Des envois qui tiennent : la cwnd grandit, SO_SNDBUF non.
    for _ in 0..3 {
        assert_eq!(ecrire(&mut c, &vec![0u8; 50 * MSS as usize]), 50 * MSS as usize);
        calmer(&mut c, &mut f);
        let _ = lire(&mut f, 1 << 30);
    }
    let cwnd = c.congestion().0 as usize;
    assert!(cwnd > 60, "cwnd {cwnd}");
    assert_eq!(c.sndbuf, depart);
    // Le programme veut écrire plus que la place : au premier segment qui part,
    // la cwnd n'étant pas pleine, SO_SNDBUF suit.
    assert_eq!(ecrire(&mut c, &vec![0u8; 2 * depart]), depart);
    assert_eq!(c.sndbuf, depart);
    for (h, o) in sortants(&mut c) {
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    assert_eq!(c.sndbuf, 2 * cwnd * (4096 + 256));
    // Il n'attend plus (tout est acquitté, la place revenue) : un envoi qui tient,
    // une autre fenêtre de congestion, SO_SNDBUF ne bouge pas.
    let n = c.sndbuf;
    calmer(&mut c, &mut f);
    let _ = lire(&mut f, 1 << 30);
    grandir(&mut c, &mut f, 2 * cwnd as u32);
    assert_eq!(c.sndbuf, n);
}

#[test]
fn newreno_un_ack_partiel_renvoie_la_perte_suivante() {
    let (mut c, mut f) = paire();
    let t0 = maintenant();
    let s = dix_segments(&mut c);
    let sixieme = s[5].0.seq;
    // Deux pertes, le premier et le sixième : la retransmission rapide
    // renvoie le premier ; son ACK s'arrête au sixième (partiel), qui
    // repart aussitôt (NewReno), toujours sans RTO.
    let renvoyes = livrer_sauf(&mut c, &mut f, s, &[0, 5]);
    assert_eq!(renvoyes.len(), 1);
    let renvoyes = livrer_sauf(&mut c, &mut f, renvoyes, &[]);
    assert_eq!(renvoyes.len(), 1);
    assert_eq!(renvoyes[0].0.seq, sixieme);
    livrer_sauf(&mut c, &mut f, renvoyes, &[]);
    assert_eq!(f.lisibles(), 10 * MSS as usize);
    assert_eq!(c.non_acquittes(), 0);
    assert_eq!(maintenant(), t0);
}

#[test]
fn fenetre_nulle_sondes_qui_doublent_puis_abandon() {
    // Un récepteur qui ne lit pas : sa fenêtre se ferme, et l'émetteur
    // sonde, le délai doublé chaque fois ; chaque sonde a sa réponse (la
    // fenêtre, toujours nulle).
    let mut c = Connexion::connecter(1, 2, 0, MSS, 131_072, 1 << 20, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 0, MSS, 16_384, 16_384, ECHELLE);
    calmer(&mut c, &mut f);
    ecrire(&mut c, &vec![7u8; 100_000]);
    calmer(&mut c, &mut f);
    assert!(c.non_envoyes() > 0);
    // Une fenêtre trop petite pour un segment entier : la sonde y met ce
    // qui tient (`tcp_write_wakeup`) ; nulle, un segment vide.
    let mut delais = Vec::new();
    while delais.len() < 4 {
        let avant = maintenant();
        echeance_suivante(&mut c);
        let s = sortants(&mut c);
        if s.is_empty() {
            continue;
        }
        if s[0].1.is_empty() {
            delais.push((maintenant() - avant) / MS);
        } else {
            delais.clear();
        }
        for (h, o) in s {
            f.recevoir(&h, Octets(o, 0), maintenant());
        }
        for (r, _) in sortants(&mut f) {
            c.recevoir(&r, vide(), maintenant());
        }
        // (`emettre` arme la sonde suivante, s'il le faut.)
        assert!(sortants(&mut c).is_empty());
    }
    // Le RTO (200 ms), doublé chaque fois.
    assert_eq!(delais, vec![200, 400, 800, 1600]);
    // Puis l'autre se tait : quinze sondes sans réponse (`tcp_retries2`),
    // et ETIMEDOUT.
    let mut sondes = 0;
    while c.etat() != Etat::Fermee {
        echeance_suivante(&mut c);
        sondes += sortants(&mut c).len();
    }
    assert_eq!((sondes, c.prendre_erreur()), (15, t::ETIMEDOUT));
}

#[test]
fn fenetre_nulle_rouverte_par_la_lecture() {
    // L'ACK qui rouvre la fenêtre se perd : la sonde suivante la découvre,
    // et l'émetteur reprend.
    let mut c = Connexion::connecter(1, 2, 0, MSS, 131_072, 1 << 20, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 0, MSS, 16_384, 16_384, ECHELLE);
    calmer(&mut c, &mut f);
    ecrire(&mut c, &vec![9u8; 50_000]);
    calmer(&mut c, &mut f);
    let lus = lire(&mut f, usize::MAX).len();
    assert!(!sortants(&mut f).is_empty());
    echeance_suivante(&mut c);
    calmer(&mut c, &mut f);
    assert!(f.lisibles() > 0);
    let mut total = lus;
    for _ in 0..1000 {
        total += lire(&mut f, usize::MAX).len();
        calmer(&mut c, &mut f);
        if total == 50_000 {
            break;
        }
    }
    assert_eq!(total, 50_000);
}

/// Une connexion établie dont l'autre côté se tait : ce qu'on écrit ne sera
/// jamais acquitté. Rend la durée jusqu'à l'abandon (ms), le nombre de
/// retransmissions et l'erreur.
fn sans_reponse(reglages: impl FnOnce(&mut Connexion), icmp: bool) -> (u64, usize, i32) {
    let (mut c, _f) = paire();
    reglages(&mut c);
    ecrire(&mut c, b"x");
    sortants(&mut c);
    let debut = maintenant();
    let mut n = 0;
    while c.etat() != Etat::Fermee {
        echeance_suivante(&mut c);
        n += sortants(&mut c).len();
        if icmp && n == 1 {
            // Un routeur dit la machine injoignable : une erreur douce.
            let una = c.numeros().0;
            c.erreur_icmp(113, una, true, false, maintenant());
        }
    }
    ((maintenant() - debut) / MS, n, c.prendre_erreur())
}

#[test]
fn abandons_comme_linux() {
    // `tcp_retries2` (15) : le temps modélisé est 924,6 s, compté depuis la
    // première retransmission (`retrans_stamp`, 0,2 s après l'envoi) ; c'est
    // un minimum (« a lower bound for the effective timeout », dit
    // ip-sysctl.rst) : l'abandon tombe au premier RTO qui le dépasse, 1 044,6 s
    // après l'envoi, seize retransmissions.
    assert_eq!(t::temps_modele(15, t::RTO_MIN) / MS, 924_600);
    assert_eq!(sans_reponse(|_| {}, false), (1_044_600, 16, t::ETIMEDOUT));
    // Une orpheline : 8 (`tcp_orphan_retries`), 102,2 s de temps modélisé ;
    // l'abandon au RTO suivant, 204,6 s après l'envoi.
    assert_eq!(sans_reponse(|c| c.reglages.orpheline = true, false), (204_600, 9, t::ETIMEDOUT));
    // TCP_USER_TIMEOUT de 5 s, compté aussi depuis la première retransmission :
    // le dernier RTO raccourci pour tomber pile.
    assert_eq!(sans_reponse(|c| c.reglages.delai_utilisateur = 5000 * MS, false).0, 5200);
    // Une erreur ICMP en route : c'est elle que rend l'abandon.
    assert_eq!(sans_reponse(|_| {}, true).2, 113);
}

#[test]
fn icmp_injoignable_defait_un_recul() {
    // RFC 6069 : pendant des retransmissions, « machine injoignable » pour
    // la tête défait un doublement du RTO.
    let (mut c, _f) = paire();
    ecrire(&mut c, b"x");
    sortants(&mut c);
    echeance_suivante(&mut c);
    let t1 = maintenant();
    sortants(&mut c);
    assert_eq!(c.echeance(), Some(t1 + c.congestion().2));
    assert_eq!(c.congestion().2 / MS, 400);
    // Un peu plus tard : le RTO défait moins ce qui a déjà passé.
    avancer(50 * MS);
    let una = c.numeros().0;
    c.erreur_icmp(113, una, true, false, maintenant());
    assert_eq!(c.congestion().2 / MS, 200);
    assert_eq!(c.echeance(), Some(t1 + c.congestion().2));
    // Déjà passé : tout de suite.
    echeance_suivante(&mut c);
    let t2 = maintenant();
    sortants(&mut c);
    avancer(300 * MS);
    let una = c.numeros().0;
    c.erreur_icmp(113, una, true, false, maintenant());
    assert!(!sortants(&mut c).is_empty(), "renvoye tout de suite");
    assert!(c.echeance().unwrap() >= t2);
}

#[test]
fn ack_retardes() {
    let (mut c, mut f) = paire();
    // Au début (« quickack »), chaque segment a son ACK tout de suite :
    // seize fois.
    for _ in 0..16 {
        ecrire(&mut c, b"a");
        assert_eq!(livrer(&mut c, &mut f), 1);
        assert_eq!(livrer(&mut f, &mut c), 1);
    }
    // Ensuite, l'ACK d'un petit segment attend 40 ms (l'`ato`), une
    // réponse à laquelle s'accrocher.
    ecrire(&mut c, b"b");
    livrer(&mut c, &mut f);
    assert!(sortants(&mut f).is_empty());
    assert_eq!(f.echeance(), Some(maintenant() + 40 * MS));
    // ... et part avec elle, si elle vient.
    ecrire(&mut f, b"reponse");
    let s = sortants(&mut f);
    assert_eq!((s.len(), s[0].1.len()), (1, 7));
    assert_eq!(f.echeance().map(|e| e > maintenant() + 40 * MS), Some(true));
    calmer(&mut c, &mut f);
    lire(&mut c, 100);
    // Sans réponse, il part à l'échéance.
    ecrire(&mut c, b"c");
    livrer(&mut c, &mut f);
    assert!(sortants(&mut f).is_empty());
    echeance_suivante(&mut f);
    assert_eq!(sortants(&mut f).len(), 1);
    // Deux segments pleins que le programme ne lit pas : la fenêtre
    // n'avance pas, l'ACK attend ; la lecture le fait partir. (Une connexion
    // neuve : dans celle-ci, le RTO a renvoyé un segment déjà reçu, et un
    // doublon remet le récepteur en mode « quickack ».)
    let (mut c, mut f) = paire();
    for _ in 0..16 {
        ecrire(&mut c, b"a");
        livrer(&mut c, &mut f);
        livrer(&mut f, &mut c);
    }
    ecrire(&mut c, &vec![1u8; 2 * MSS as usize]);
    livrer(&mut c, &mut f);
    assert!(sortants(&mut f).is_empty());
    lire(&mut f, usize::MAX);
    assert_eq!(sortants(&mut f).len(), 1);
}

#[test]
fn fin_apres_un_trou() {
    // Le FIN arrive avant les dernières données : il attend que le trou se
    // comble.
    let (mut c, mut f) = paire();
    ecrire(&mut c, b"abc");
    let donnees = sortants(&mut c);
    c.fermer_envoi();
    let fin = sortants(&mut c);
    assert_eq!(fin[0].0.drapeaux & tcp::FIN, tcp::FIN);
    f.recevoir(&fin[0].0, vide(), maintenant());
    assert_eq!((f.etat(), f.fin_recue()), (Etat::Etablie, false));
    assert_eq!(sortants(&mut f)[0].0.ack, donnees[0].0.seq);
    f.recevoir(&donnees[0].0, Octets(donnees[0].1.clone(), 0), maintenant());
    assert_eq!((f.etat(), f.fin_recue(), f.lisibles()), (Etat::AttenteFermeture, true, 3));
    calmer(&mut c, &mut f);
    assert_eq!(c.etat(), Etat::FinAttente2);
}

/// Deux connexions désynchronisées (chacune a fait sa poignée de main avec
/// un autre pair) : chacune trouve les segments de l'autre hors de sa
/// fenêtre. Leurs ACK s'arrêtent vite : un ACK hors fenêtre (sans données)
/// au plus toutes les 500 ms par connexion (`tcp_oow_rate_limited`) ; et
/// de même un ACK de défi.
#[test]
fn ack_hors_fenetre_limites() {
    let (mut a, _a0) = paire();
    let mut c = Connexion::connecter(40000, 80, 2_000_000_000, MSS, 131_072, 16_384, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut b = Connexion::depuis_syn(&syn, 3_000_000_000, MSS, 131_072, 16_384, ECHELLE);
    calmer(&mut c, &mut b);
    ecrire(&mut a, b"x");
    let mut vers_b = sortants(&mut a);
    let mut echanges = 0;
    while !vers_b.is_empty() && echanges < 100 {
        let mut vers_a = Vec::new();
        for (h, o) in vers_b.drain(..) {
            b.recevoir(&h, Octets(o, 0), maintenant());
            vers_a.extend(sortants(&mut b));
        }
        for (h, o) in vers_a {
            a.recevoir(&h, Octets(o, 0), maintenant());
            vers_b.extend(sortants(&mut a));
        }
        echanges += 1;
    }
    assert!(echanges <= 3, "{echanges} allers-retours d'ACK");
    // Un RST dans la fenêtre, hors du bord : un ACK de défi, puis plus
    // rien pendant 500 ms ; ensuite, un autre.
    let (mut c, _f) = paire();
    let rst = Tcp { drapeaux: tcp::RST, seq: bord(&c).wrapping_add(10), ..Tcp::default() };
    c.recevoir(&rst, vide(), maintenant());
    assert_eq!(sortants(&mut c).len(), 1);
    c.recevoir(&rst, vide(), maintenant());
    assert!(sortants(&mut c).is_empty());
    avancer(500 * MS);
    c.recevoir(&rst, vide(), maintenant());
    assert_eq!(sortants(&mut c).len(), 1);
}

/// Une connexion établie aux tampons et MSS donnés.
fn paire_avec(mss: u16, rcvbuf: usize, sndbuf: usize) -> (Connexion, Connexion) {
    let mut c = Connexion::connecter(40000, 80, 1000, mss, rcvbuf, sndbuf, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, mss, rcvbuf, sndbuf, ECHELLE);
    calmer(&mut c, &mut f);
    assert_eq!((c.etat(), f.etat()), (Etat::Etablie, Etat::Etablie));
    (c, f)
}

/// Après le « quickack » du début, deux segments pleins reçus quand la
/// fenêtre ne recule pas (un SO_RCVBUF au-delà de ce que l'échelle peut
/// annoncer : elle reste à sa borne, 8 Mio) : un ACK tout de suite, un pour
/// deux segments (RFC 5681 4.2, `__tcp_ack_snd_check`) ; un seul attend.
#[test]
fn ack_au_deuxieme_segment_plein() {
    let (mut c, mut f) = paire_avec(MSS, 131_072, 1 << 20);
    for _ in 0..16 {
        ecrire(&mut c, b"a");
        livrer(&mut c, &mut f);
        livrer(&mut f, &mut c);
    }
    calmer(&mut c, &mut f);
    // La fenêtre se pose : jusque-là, la promesse du SYN, un peu plus grande que ce
    // que SO_RCVBUF permet ensuite, retarde les ACK (ce que Linux fait aussi).
    ecrire(&mut c, &vec![1u8; 4 * MSS as usize]);
    calmer(&mut c, &mut f);
    let _ = lire(&mut f, 1 << 20);
    calmer(&mut c, &mut f);
    ecrire(&mut c, &vec![2u8; MSS as usize]);
    livrer(&mut c, &mut f);
    assert!(sortants(&mut f).is_empty());
    ecrire(&mut c, &vec![3u8; MSS as usize]);
    livrer(&mut c, &mut f);
    assert_eq!(sortants(&mut f).len(), 1);
}

// --- La réception qui s'ajuste (reception.rs) ---

/// Un SYN et un SYN-ACK : la fenêtre de chaque connexion, et ce qu'elles annoncent.
fn poignee(mss: u16, rcvbuf: usize, echelle: u8, horodatages: bool, regler: impl Fn(&mut Connexion)) -> (Connexion, Connexion, u16, u16) {
    let mut c = Connexion::connecter(40000, 80, 1000, mss, rcvbuf, 16_384, echelle);
    regler(&mut c);
    if horodatages {
        c.proposer_horodatages(1);
    }
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, mss, rcvbuf, 16_384, echelle);
    regler(&mut f);
    let s = sortants(&mut f)[0].0;
    c.recevoir(&s, vide(), maintenant());
    (c, f, syn.fenetre, s.fenetre)
}

/// `tcp_select_initial_window`, comme Linux (mesuré sur `lo`, et bien connu sur
/// Ethernet) : le plein de SO_RCVBUF (131 072, à 50 %) arrondi au MSS annoncé, moins
/// les options pour la fille. Sur `lo` : 65 495 et 65 483. Sur Ethernet : 64 240, et
/// 64 240 pour une fille sans horodatages. Le premier ACK dit 65 536 sur `lo`, 64 256
/// sur Ethernet (64 240 promis, arrondis à l'échelle).
#[test]
fn fenetre_initiale_comme_linux() {
    let (mut c, _, syn, synack) = poignee(65_495, 131_072, 7, true, |_| {});
    assert_eq!((syn, synack), (65_495, 65_483));
    let ack = sortants(&mut c)[0].0;
    assert_eq!(ack.fenetre as u32 * 128, 65_536);
    let (mut c, _, syn, synack) = poignee(1460, 131_072, 7, false, |_| {});
    assert_eq!((syn, synack), (64_240, 64_240));
    let ack = sortants(&mut c)[0].0;
    assert_eq!(ack.fenetre as u32 * 128, 64_256);
    // Sans échelle chez l'autre : au plus 65 535, sur 16 bits sans décalage.
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 1 << 20, 16_384, 7);
    let mut syn = sortants(&mut c)[0].0;
    assert_eq!(syn.fenetre, 65_535);
    syn.options.echelle = None;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 1 << 20, 16_384, 7);
    let s = sortants(&mut f)[0].0;
    assert_eq!((s.fenetre, s.options.echelle), (65_535, None));
    // SO_RCVBUF fixé : sa moitié, et le plafond tient compte de l'unique segment réservé.
    let (c, _, syn, _) = poignee(1460, 16_384, 0, false, |t| t.rcvbuf_fixe = true);
    assert_eq!((syn, c.window_clamp), (7300, 8192 - 1460));
    // TCP_WINDOW_CLAMP : la fenêtre, et ce qui suit.
    let (c, _, syn, _) = poignee(1460, 131_072, 0, false, |t| t.window_clamp = 5000);
    assert_eq!((syn, c.window_clamp), (4380, 5000));
}

/// La promesse tient : une fenêtre annoncée ne recule pas, même quand la place manque
/// (`tcp_select_window`) ; elle revient à ce que permet la place, le bord étant passé.
#[test]
fn la_fenetre_ne_recule_pas() {
    let (mut c, mut f) = paire();
    calmer(&mut c, &mut f);
    let (_, _, r0) = f.numeros();
    let bord0 = r0.wrapping_add(f.fenetre_annoncee());
    for _ in 0..8 {
        ecrire(&mut c, &vec![1u8; 4 * MSS as usize]);
        calmer(&mut c, &mut f);
        let (_, _, r) = f.numeros();
        assert!(!t::avant(r.wrapping_add(f.fenetre_annoncee()), bord0));
    }
}

/// `rcv_ssthresh` monte par paliers, pour des segments de bon rendement (le rapport
/// mesuré suit), jamais au-delà du plafond ; une fenêtre annoncée le suit. Sous
/// pression : quatre segments (`tcp_adjust_rcv_ssthresh`).
#[test]
fn le_seuil_de_la_fenetre_monte_par_paliers() {
    let (mut c, mut f) = paire_avec(MSS, 131_072, 1 << 22);
    // De la place en réserve (DRS en donnerait) : le seuil part de la fenêtre du SYN.
    f.rcvbuf = 1 << 22;
    f.poser_fenetre_max(1 << 21);
    let debut = f.info(maintenant()).rcv_ssthresh;
    assert!(debut < 65_536);
    let mut suite = Vec::new();
    for _ in 0..30 {
        ecrire(&mut c, &vec![1u8; 10 * MSS as usize]);
        calmer(&mut c, &mut f);
        let _ = lire(&mut f, 1 << 24);
        suite.push(f.info(maintenant()).rcv_ssthresh);
    }
    assert!(suite.windows(2).all(|d| d[0] <= d[1]), "{suite:?}");
    assert!(*suite.last().unwrap() >= debut + 100 * MSS as u32, "{debut} puis {suite:?}");
    assert!(*suite.last().unwrap() <= f.window_clamp);
    let i = f.info(maintenant());
    assert!(i.rcv_wnd > 0);
    // Sous pression.
    f.memoire = t::Memoire::Pression;
    ecrire(&mut c, &vec![1u8; 2 * MSS as usize]);
    calmer(&mut c, &mut f);
    assert!(f.info(maintenant()).rcv_ssthresh <= 4 * MSS as u32, "{}", f.info(maintenant()).rcv_ssthresh);
}

/// Un aller-retour de données, un RTT de 10 ms : `tours` fois le programme lit ce
/// qui arrive, `n` segments par tour. Rend le SO_RCVBUF de la fille.
fn transfert(c: &mut Connexion, f: &mut Connexion, tours: usize, n: usize, lit: bool) -> usize {
    for _ in 0..tours {
        ecrire(c, &vec![1u8; n * MSS as usize]);
        loop {
            let s = sortants(c);
            if s.is_empty() {
                break;
            }
            avancer(5 * MS);
            for (h, o) in s {
                f.recevoir(&h, Octets(o, 0), maintenant());
            }
            if lit {
                let _ = lire(f, 1 << 30);
            }
            let r = sortants(f);
            avancer(5 * MS);
            for (h, _) in r {
                c.recevoir(&h, vide(), maintenant());
            }
        }
        calmer(c, f);
    }
    f.rcvbuf
}

/// Dynamic Right Sizing (`tcp_rcv_space_adjust`, `tcp_rcvbuf_grow`) : SO_RCVBUF suit ce
/// que le programme lit en un RTT, jusqu'à `tcp_rmem[2]`. Pas s'il est fixé ; pas si le
/// programme ne lit pas (le RTT du récepteur fait la mesure).
#[test]
fn so_rcvbuf_suit_le_debit() {
    let (mut c, mut f) = paire_avec(MSS, 131_072, 1 << 24);
    f.proposer_horodatages(0);
    f.rcvbuf_max = 1 << 24;
    let apres = transfert(&mut c, &mut f, 20, 40, true);
    assert!(apres > 131_072, "{apres}");
    assert!(apres <= 1 << 24);
    let i = f.info(maintenant());
    assert!(i.rcv_space > 64_240 && i.rcv_rtt > 0, "{} {}", i.rcv_space, i.rcv_rtt);
    // Le plafond.
    let (mut c, mut f) = paire_avec(MSS, 131_072, 1 << 24);
    f.rcvbuf_max = 200_000;
    assert_eq!(transfert(&mut c, &mut f, 20, 40, true), 200_000);
    // Fixé : il ne bouge pas.
    let (mut c, mut f) = paire_avec(MSS, 131_072, 1 << 24);
    f.rcvbuf_fixe = true;
    assert_eq!(transfert(&mut c, &mut f, 20, 40, true), 131_072);
    // Le programme ne lit pas : la fenêtre se ferme, il ne fait rien grandir.
    let (mut c, mut f) = paire_avec(MSS, 131_072, 1 << 24);
    assert!(transfert(&mut c, &mut f, 1, 40, false) <= 131_072 + 3000);
}

/// Le rapport (`scaling_ratio`) est mesuré : un segment plein de rendement 50 %
/// environ, la fenêtre suit ; deux petits segments égaux, sans PSH ni le reste : c'est
/// le MSS de l'autre (`tcp_measure_rcv_mss`, `last_seg_size`).
#[test]
fn rcv_mss_et_rapport() {
    let (_c, mut f) = paire();
    let bord = bord(&f);
    let modele = Tcp { drapeaux: tcp::ACK, ack: f.numeros().0, fenetre: 65_535, ..Tcp::default() };
    assert_eq!(f.info(maintenant()).rcv_mss, 536);
    f.recevoir(&Tcp { seq: bord, ..modele }, Octets(vec![1; 300], 0), maintenant());
    assert_eq!(f.info(maintenant()).rcv_mss, 536, "un seul : rien");
    f.recevoir(&Tcp { seq: bord.wrapping_add(300), ..modele }, Octets(vec![1; 300], 0), maintenant());
    assert_eq!(f.info(maintenant()).rcv_mss, 300, "deux de suite : c'est son MSS");
    f.recevoir(&Tcp { seq: bord.wrapping_add(600), ..modele }, Octets(vec![1; 1000], 0), maintenant());
    assert_eq!(f.info(maintenant()).rcv_mss, 1000);
    // Pas au-delà de ce qu'on a annoncé (une agrégation, chez d'autres).
    f.recevoir(&Tcp { seq: bord.wrapping_add(1600), ..modele }, Octets(vec![1; 9000], 0), maintenant());
    assert_eq!(f.info(maintenant()).rcv_mss, MSS as u32);
}

/// `tcp_cleanup_rbuf` : une lecture qui vide tout, après un petit segment (l'autre a
/// peut-être fini, et attend), fait partir un ACK, hors d'une conversation.
#[test]
fn lecture_qui_vide_tout_fait_partir_l_ack() {
    let (mut c, mut f) = paire();
    // Assez d'ACK rapides pour en sortir.
    for _ in 0..20 {
        ecrire(&mut c, b"a");
        calmer(&mut c, &mut f);
        lire(&mut f, 1);
    }
    let r = t::Reglages { nodelay: true, ..c.reglages };
    c.regler(r, maintenant());
    // Sortir aussi du ping-pong.
    f.quickack(false);
    f.quickack(true);
    ecrire(&mut c, b"z");
    livrer(&mut c, &mut f);
    let delai = sortants(&mut f).len();
    if delai == 0 {
        assert_eq!(lire(&mut f, 1), b"z");
        assert_eq!(sortants(&mut f).len(), 1);
    }
}

/// La mémoire manque, malgré tout (SO_RCVBUF fixé, la file pleine) : le segment est
/// jeté, et l'ACK annonce une fenêtre nulle (ICSK_ACK_NOMEM) ; la lecture la rouvre.
#[test]
fn fenetre_nulle_quand_la_memoire_manque() {
    let (_c, mut f) = paire_avec(MSS, 16_384, 16_384);
    f.rcvbuf_fixe = true;
    let bord = bord(&f);
    let modele = Tcp { drapeaux: tcp::ACK, ack: f.numeros().0, fenetre: 65_535, ..Tcp::default() };
    // Plus de mémoire pour TCP : le premier, la file vide, est gardé quand même (la
    // connexion doit avancer), avec une fenêtre nulle.
    f.memoire = t::Memoire::Limite;
    f.recevoir(&Tcp { seq: bord, ..modele }, Octets(vec![1; 100], 0), maintenant());
    assert_eq!(f.lisibles(), 100);
    let s = sortants(&mut f);
    assert_eq!((s.len(), s[0].0.fenetre), (1, 0));
    assert_eq!(f.fenetre_annoncee(), 0);
    // La fenêtre fermée : jeté, et l'ACK dit ce qui reste de place : ce n'est pas
    // SO_RCVBUF qui manque.
    f.recevoir(&Tcp { seq: bord.wrapping_add(100), ..modele }, Octets(vec![1; 100], 0), maintenant());
    assert_eq!(f.lisibles(), 100);
    assert!(sortants(&mut f)[0].0.fenetre > 0);
    // Il y a de quoi lire : le suivant est jeté, et de nouveau une fenêtre nulle.
    f.recevoir(&Tcp { seq: bord.wrapping_add(100), ..modele }, Octets(vec![1; 100], 0), maintenant());
    assert_eq!(f.lisibles(), 100);
    assert_eq!(sortants(&mut f)[0].0.fenetre, 0);
    // La mémoire revient, le programme lit : la fenêtre se rouvre.
    f.memoire = t::Memoire::Libre;
    lire(&mut f, 100);
    let s = sortants(&mut f);
    assert!(s[0].0.fenetre > 0, "{:?}", s[0].0.fenetre);
}

/// `tcp_collapse` : la mémoire manque pour de tout petits segments : la file de
/// lecture est recopiée, dense, sans qu'un octet change ni se perde. Et SO_RCVBUF, s'il
/// n'est pas fixé, a suivi ce que garde la file (`tcp_clamp_window`).
#[test]
fn file_de_lecture_fondue() {
    let (_c, mut f) = paire_avec(MSS, 16_384, 16_384);
    f.rcvbuf_fixe = true;
    let bord = bord(&f);
    let modele = Tcp { drapeaux: tcp::ACK, ack: f.numeros().0, fenetre: 65_535, ..Tcp::default() };
    let n = 2000u32;
    for i in 0..n {
        f.recevoir(&Tcp { seq: bord.wrapping_add(i), ..modele }, Octets(vec![i as u8], 0), maintenant());
    }
    assert_eq!(f.lisibles(), n as usize);
    assert!(f.memoire_reception() <= 16_384 + 66, "{}", f.memoire_reception());
    let lu = lire(&mut f, 1 << 20);
    assert_eq!(lu, (0..n).map(|i| i as u8).collect::<Vec<u8>>());
    assert_eq!(f.memoire_reception(), 0);
    // Pas fixé : la limite suit, sans qu'on fonde tant qu'elle grandit.
    let (_c, mut f) = paire_avec(MSS, 16_384, 16_384);
    let bord = crate::bord(&f);
    for i in 0..n {
        f.recevoir(&Tcp { seq: bord.wrapping_add(i), ..modele }, Octets(vec![i as u8], 0), maintenant());
    }
    assert_eq!(f.lisibles(), n as usize);
    assert!(f.rcvbuf >= 16_384);
    assert_eq!(lire(&mut f, 1 << 20), (0..n).map(|i| i as u8).collect::<Vec<u8>>());
}

/// TCP_WINDOW_CLAMP en route (`tcp_set_window_clamp`) : plus bas, le seuil baisse aussi ;
/// plus haut, le seuil remonte jusqu'à la fenêtre annoncée. Au moins 1152.
#[test]
fn window_clamp_en_route() {
    let (_c, mut f) = paire();
    let ss = f.info(maintenant()).rcv_ssthresh;
    f.poser_fenetre_max(3000);
    assert_eq!((f.window_clamp, f.info(maintenant()).rcv_ssthresh), (3000, 3000));
    f.poser_fenetre_max(100);
    assert_eq!(f.window_clamp, 1152);
    f.poser_fenetre_max(1 << 20);
    assert_eq!((f.window_clamp, f.info(maintenant()).rcv_ssthresh), (1 << 20, f.info(maintenant()).rcv_wnd.min(1 << 20).max(1152)));
    let _ = ss;
}

/// SO_RCVLOWAT (`tcp_set_rcvlowat`) : borné par la moitié de `tcp_rmem[2]`, ou de SO_RCVBUF
/// s'il est fixé ; SO_RCVBUF grandit pour le tenir, sauf s'il est fixé.
#[test]
fn rcvlowat_de_tcp() {
    let (_c, mut f) = paire_avec(MSS, 131_072, 16_384);
    f.rcvbuf_max = 1 << 20;
    assert_eq!(f.poser_rcvlowat(100), 100);
    assert_eq!(f.rcvbuf, 131_072);
    assert_eq!(f.poser_rcvlowat(100_000), 100_000);
    assert!(f.rcvbuf >= 200_000);
    assert_eq!(f.poser_rcvlowat(u32::MAX), 1 << 19);
    assert_eq!(f.poser_rcvlowat(0), 1);
    let (_c, mut f) = paire_avec(MSS, 16_384, 16_384);
    f.rcvbuf_fixe = true;
    assert_eq!(f.poser_rcvlowat(100_000), 8192);
    assert_eq!(f.rcvbuf, 16_384);
}

// --- Ce qu'a trouvé la relecture de `tcp_ack` et de ses voisins ---

/// Deux blocs neufs dans un même ACK, le plus récent en tête : pas de réordonnancement
/// (`tcp_sacktag_write_queue` les trie).
#[test]
fn sack_deux_blocs_neufs_pas_de_reordonnancement() {
    let (mut c, mut f) = paire_avec_sack();
    assert_eq!(ecrire(&mut c, &vec![0u8; 8 * MSS as usize]), 8 * MSS as usize);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 8);
    // Le dernier reçu d'abord, puis un plus bas : l'ACK dit le plus récent en tête.
    f.recevoir(&s[1].0, Octets(s[1].1.clone(), 0), maintenant());
    f.recevoir(&s[5].0, Octets(s[5].1.clone(), 0), maintenant());
    let a = sortants(&mut f);
    let ack = a.last().unwrap().0;
    assert!(ack.options.nb_blocs >= 2);
    assert!(apres_seq(ack.options.blocs[0].0, ack.options.blocs[1].0));
    c.recevoir(&ack, vide(), maintenant());
    let i = c.info(maintenant());
    assert_eq!((i.reord_seen, i.reordonnancement, i.sackes), (0, 3, 2));
}

/// Un D-SACK au milieu d'un bloc : ses segments sont des doublons, le reste non ; un seul passage.
#[test]
fn sack_un_doublon_dans_un_bloc() {
    let (mut c, _f) = paire_avec_sack();
    let m = MSS as u32;
    assert_eq!(ecrire(&mut c, &vec![0u8; 8 * MSS as usize]), 8 * MSS as usize);
    let s = sortants(&mut c);
    let una = s[0].0.seq;
    // Le segment 3 renvoyé, et son doublon dit au milieu d'un bloc qui couvre 2..5.
    let mut h = Tcp { source: 80, destination: 40000, seq: s[0].0.ack, ack: una, drapeaux: tcp::ACK, fenetre: s[0].0.fenetre, urgent: 0, options: tcp::Options::default() };
    h.options.blocs[0] = (una + 3 * m, una + 4 * m);
    h.options.blocs[1] = (una + 2 * m, una + 5 * m);
    h.options.nb_blocs = 2;
    c.recevoir(&h, vide(), maintenant());
    let i = c.info(maintenant());
    assert_eq!((i.sackes, i.dsack_doublons, i.reord_seen), (3, 1, 0));
}

fn apres_seq(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Une connexion avec SACK, à toute heure.
fn paire_avec_sack() -> (Connexion, Connexion) {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.proposer_sack();
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    f.proposer_sack();
    let sa = sortants(&mut f)[0].0;
    c.recevoir(&sa, vide(), maintenant());
    livrer(&mut c, &mut f);
    (c, f)
}

/// Une fille ne garde rien de sa poignée de main pour ses RTO : ni l'heure de son SYN-ACK, ni son
/// recul (`tcp_rcv_state_process` : `retrans_stamp = 0` ; `inet_csk_clone_lock`).
#[test]
fn une_vieille_fille_abandonne_comme_les_autres() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    let sa = sortants(&mut f)[0].0;
    c.recevoir(&sa, vide(), maintenant());
    let ack = sortants(&mut c)[0].0;
    echeance_suivante(&mut f);
    sortants(&mut f);
    f.recevoir(&ack, vide(), maintenant());
    assert_eq!((f.etat(), f.info(maintenant()).recul), (Etat::Etablie, 0));
    // 1000 s de silence, puis une perte : 15 minutes de renvois, pas deux.
    avancer(1000 * 1000 * MS);
    let t0 = maintenant();
    assert_eq!(ecrire(&mut f, b"x"), 1);
    sortants(&mut f);
    let mut rto = 0;
    while f.etat() != Etat::Fermee {
        echeance_suivante(&mut f);
        sortants(&mut f);
        rto += 1;
    }
    assert!(maintenant() - t0 > 900 * 1000 * MS, "abandon apres {} ms, {rto} RTO", (maintenant() - t0) / MS);
}

/// Une connexion sans SACK, avec les horodatages.
fn reno_avec_horodatages() -> (Connexion, Connexion) {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 1 << 22, 1 << 22, ECHELLE);
    c.proposer_horodatages(1_000_000);
    let (syn, _) = sortants(&mut c)[0];
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 1 << 22, 1 << 22, ECHELLE);
    f.decalage_horodatages(5_000_000);
    let s = sortants(&mut f);
    c.recevoir(&s[0].0, vide(), maintenant());
    livrer(&mut c, &mut f);
    calmer(&mut c, &mut f);
    (c, f)
}

/// Une reprise sans SACK, et un ACK partiel de `segments`, dont l'écho précède le renvoi : l'original
/// est arrivé : un réordonnancement, compté depuis la tête (`tcp_try_undo_partial`).
fn reno_ack_partiel(c: &mut Connexion, segments: u32) -> t::Info {
    let mss = MSS as u32 - 12;
    avancer(100 * MS);
    assert_eq!(ecrire(c, &vec![1u8; 8 * mss as usize]), 8 * mss as usize);
    let s = sortants(c);
    assert_eq!(s.len(), 8);
    let (val0, recent) = s[0].0.options.horodatage.unwrap();
    let (una, _, _) = c.numeros();
    avancer(10 * MS);
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(c), ack: una, fenetre: 65_535, options: tcp::Options { horodatage: Some((recent, val0)), ..Default::default() }, ..Tcp::default() };
    for _ in 0..4 {
        c.recevoir(&m, vide(), maintenant());
    }
    assert_eq!(c.info(maintenant()).phase, 3);
    let s = sortants(c);
    assert_eq!(s[0].0.seq, una);
    avancer(10 * MS);
    c.recevoir(&Tcp { ack: una.wrapping_add(segments * mss), ..m }, vide(), maintenant());
    c.info(maintenant())
}

/// Sans SACK, le plus haut « SACKé » est la tête (`tcp_highest_sack_replace`).
#[test]
fn reno_annulation_partielle_compte_le_reordonnancement() {
    let (mut c, _f) = reno_avec_horodatages();
    let i = reno_ack_partiel(&mut c, 5);
    assert_eq!((i.reord_seen, i.reordonnancement), (1, 5));
}

/// Même après 2 Gio : un `fack` resté à l'ISS tomberait « devant » SND.UNA, à l'écart de presque
/// 2^31, et `reordering` à 300 : plus de retransmission rapide.
#[test]
fn reno_apres_2_gio() {
    let (mut c, _f) = reno_avec_horodatages();
    let mss = MSS as u32 - 12;
    let bloc = vec![1u8; 8 * mss as usize];
    let mut fait = 0u64;
    while fait < (1u64 << 31) + 16 * mss as u64 {
        avancer(MS);
        assert_eq!(ecrire(&mut c, &bloc), bloc.len());
        let s = sortants(&mut c);
        let (val0, recent) = s[0].0.options.horodatage.unwrap();
        let (_, nxt, _) = c.numeros();
        let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: nxt, fenetre: 65_535, options: tcp::Options { horodatage: Some((recent, val0)), ..Default::default() }, ..Tcp::default() };
        avancer(MS);
        c.recevoir(&m, vide(), maintenant());
        fait += bloc.len() as u64;
    }
    assert_eq!(c.info(maintenant()).reordonnancement, 3);
    assert!(reno_ack_partiel(&mut c, 1).reordonnancement <= 3);
}

/// Sans SACK, accoler de petits segments en retire de la file : aussi du compte des ACK dupliqués
/// (`tcp_adjust_pcount`).
#[test]
fn reno_accoler_rend_les_ack_dupliques() {
    let (mut c, mut f) = paire();
    calmer(&mut c, &mut f);
    let mut r = c.reglages;
    r.nodelay = true;
    c.regler(r, maintenant());
    for _ in 0..6 {
        assert_eq!(ecrire(&mut c, &[1u8; 100]), 100);
        assert_eq!(sortants(&mut c).len(), 1);
    }
    let (una, _, _) = c.numeros();
    avancer(MS);
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 65_535, ..Tcp::default() };
    // Le premier ne compte pas : il met la fenêtre à jour.
    for _ in 0..4 {
        c.recevoir(&m, vide(), maintenant());
    }
    let r = sortants(&mut c);
    assert_eq!(r[0].1.len(), 600, "le renvoi accole");
    let i = c.info(maintenant());
    assert_eq!((i.non_acquittes, i.sackes, i.perdus), (1, 0, 1));
}

/// `tcpi_last_data_recv` compte depuis l'établissement, pas depuis le démarrage de la machine.
#[test]
fn info_derniere_reception_depuis_l_etablissement() {
    let (c, f) = paire();
    assert_eq!((c.info(maintenant()).dernier_recu, f.info(maintenant()).dernier_recu), (0, 0));
}

/// Un vieil ACK ne compte pas ses SACK dans ce qui est livré (`old_ack`).
#[test]
fn un_vieil_ack_ne_livre_rien() {
    let (mut c, _f) = paire_avec_sack();
    let m = MSS as u32;
    assert_eq!(ecrire(&mut c, &vec![0u8; 6 * MSS as usize]), 6 * MSS as usize);
    let s = sortants(&mut c);
    let una = s[0].0.seq;
    let mut h = Tcp { source: 80, destination: 40000, seq: s[0].0.ack, ack: una + m, drapeaux: tcp::ACK, fenetre: s[0].0.fenetre, urgent: 0, options: tcp::Options::default() };
    c.recevoir(&h, vide(), maintenant());
    let livres = c.info(maintenant()).livres;
    // En retard : son ACK est sous SND.UNA, son bloc est neuf.
    h.ack = una;
    h.options.blocs[0] = (una + 3 * m, una + 4 * m);
    h.options.nb_blocs = 1;
    c.recevoir(&h, vide(), maintenant());
    assert_eq!(c.info(maintenant()).livres, livres);
}

/// Une connexion avec SACK, un aller-retour de mesuré, et une carte.
fn par_une_carte_sack() -> (Connexion, Connexion) {
    let (mut c, mut f) = paire_avec_sack();
    assert_eq!(ecrire(&mut c, b"a"), 1);
    livrer(&mut c, &mut f);
    avancer(10 * MS);
    f.quickack(true);
    assert!(livrer(&mut f, &mut c) >= 1);
    c.sans_file = false;
    (c, f)
}

/// La sonde de fin de rafale passe par `tcp_write_xmit` : TSQ peut lui dire non.
#[test]
fn tlp_et_tsq() {
    let (mut c, _f) = par_une_carte_sack();
    let cwnd = c.congestion().0 as usize;
    assert_eq!(ecrire(&mut c, &vec![1u8; (cwnd + 1) * MSS as usize]), (cwnd + 1) * MSS as usize);
    c.poser_en_file(0, u64::MAX);
    assert_eq!(sortants(&mut c).len(), cwnd);
    avancer(c.echeance().unwrap() - maintenant());
    c.minuteur(maintenant());
    c.poser_en_file(8 << 20, u64::MAX);
    assert!(sortants(&mut c).is_empty(), "tcp_small_queue_check : rien ne part");
}

/// Du neuf part alors que la sonde de fin de rafale est armée, la reprise ouverte et la tête encore
/// dans la carte : c'est le RTO qui reprend (`tcp_event_new_data_sent`).
#[test]
fn neuf_en_reprise_le_tlp_laisse_la_place_au_rto() {
    let (mut c, _f) = par_une_carte_sack();
    let m = MSS as u32;
    assert_eq!(ecrire(&mut c, &vec![1u8; 6 * MSS as usize]), 6 * MSS as usize);
    c.poser_en_file(0, u64::MAX);
    assert_eq!(sortants(&mut c).len(), 6);
    let (una, _, _) = c.numeros();
    let tlp = c.echeance().unwrap() - maintenant();
    assert!(tlp < c.congestion().2);
    let t0 = maintenant();
    avancer(MS);
    let mut o = tcp::Options { nb_blocs: 1, ..Default::default() };
    o.blocs[0] = (una + m, una + 5 * m);
    let h = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 65_535, options: o, ..Tcp::default() };
    c.recevoir(&h, vide(), maintenant());
    assert_eq!(c.info(maintenant()).phase, 3);
    assert_eq!(c.echeance(), Some(t0 + tlp), "le minuteur reste celui de la sonde");
    // La carte a toujours tout : la tête ne repart pas ; du neuf part.
    assert_eq!(ecrire(&mut c, &vec![2u8; MSS as usize]), MSS as usize);
    c.poser_en_file(0, 0);
    let s = sortants(&mut c);
    assert!(s.iter().any(|x| !x.1.is_empty()), "du neuf");
    assert_eq!(c.echeance(), Some(t0 + c.congestion().2), "le RTO, depuis l'envoi de la tete");
}

/// Sans SACK, le SYN renvoyé laisse l'état de perte jusqu'au premier ACK au-delà (`tcp_is_non_sack_preventing_reopen`) ;
/// avec SACK, il rouvre.
#[test]
fn syn_renvoye_et_l_etat_de_perte() {
    for sack in [false, true] {
        let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
        if sack {
            c.proposer_sack();
        }
        let syn = sortants(&mut c)[0].0;
        echeance_suivante(&mut c);
        sortants(&mut c);
        assert_eq!(c.info(maintenant()).phase, 4);
        let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
        if sack {
            f.proposer_sack();
        }
        let sa = sortants(&mut f)[0].0;
        c.recevoir(&sa, vide(), maintenant());
        assert_eq!(c.info(maintenant()).phase, if sack { 0 } else { 4 });
        livrer(&mut c, &mut f);
        f.quickack(true);
        assert_eq!(ecrire(&mut c, b"a"), 1);
        livrer(&mut c, &mut f);
        assert!(livrer(&mut f, &mut c) >= 1);
        assert_eq!(c.info(maintenant()).phase, 0);
    }
}

/// La sonde de fenêtre porte PSH, même coupée (`tcp_write_wakeup`).
#[test]
fn sonde_coupee_porte_psh() {
    let (mut c, _f) = fenetre_fermee(32 * 1024);
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    let una = s[0].0.seq.wrapping_add(1);
    let mut h = Tcp { source: 80, destination: 40000, seq: s[0].0.ack, ack: una, drapeaux: tcp::ACK, fenetre: 1, urgent: 0, options: tcp::Options::default() };
    h.options.horodatage = s[0].0.options.horodatage.map(|(v, e)| (e, v));
    c.recevoir(&h, vide(), maintenant());
    assert!(sortants(&mut c).is_empty());
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    assert_eq!((s.len(), s[0].0.drapeaux & tcp::PSH), (1, tcp::PSH));
    assert_eq!(s[0].1.len(), 1 << ECHELLE);
}

/// La fille prend la fenêtre de son troisième ACK : `max_fenetre` n'a rien à garder du SYN
/// (`tcp_create_openreq_child`), et le MSS suit sa moitié (`tcp_bound_to_half_wnd`).
#[test]
fn la_fille_oublie_la_fenetre_de_son_syn() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, 0);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, 0);
    let sa = sortants(&mut f)[0].0;
    c.recevoir(&sa, vide(), maintenant());
    let mut ack = sortants(&mut c)[0].0;
    ack.fenetre = 1000;
    f.recevoir(&ack, vide(), maintenant());
    assert_eq!(f.etat(), Etat::Etablie);
    assert_eq!(f.info(maintenant()).snd_mss, 500);
}

// --- La sonde de fenêtre (`tcp_write_wakeup`, `tcp_send_probe0`) ---

/// Une fenêtre fermée à l'autre bout, des données qui attendent : la connexion, et sa fille.
fn fenetre_fermee(octets: usize) -> (Connexion, Connexion) {
    let (mut c, mut f) = paire_avec(MSS, 2048, 262_144);
    assert_eq!(ecrire(&mut c, &vec![0u8; octets]), octets);
    calmer(&mut c, &mut f);
    assert_eq!(c.info(maintenant()).non_acquittes, 0);
    assert!(c.info(maintenant()).non_envoyes > 0);
    assert_eq!(c.info(maintenant()).snd_wnd, 0);
    (c, f)
}

/// Un ACK de la fille, à refaire à sa guise.
fn sortants_de_fille(f: &mut Connexion, c: &mut Connexion) -> Tcp {
    // Une sonde de plus lui en fait dire un.
    echeance_suivante(c);
    let s = sortants(c);
    f.recevoir(&s[0].0, vide(), maintenant());
    sortants(f)[0].0
}

/// Un octet urgent en attente : avant la sonde, un segment au numéro attendu, qui porte le
/// pointeur (`tcp_xmit_probe_skb(sk, 1, mib)`).
#[test]
fn sonde_avec_un_octet_urgent() {
    let (mut c, _f) = fenetre_fermee(32 * 1024);
    // Sans urgent : la sonde seule, en deçà de ce qui est attendu.
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    let una = s[0].0.seq.wrapping_add(1);
    assert_eq!((s.len(), s[0].1.len(), s[0].0.drapeaux & tcp::URG), (1, 0, 0));
    assert_eq!(c.info(maintenant()).sondes, 1);
    // Avec.
    assert_eq!(ecrire(&mut c, b"u"), 1);
    c.marquer_urgent();
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 2);
    assert_eq!((s[0].0.seq, s[0].0.drapeaux & tcp::URG, s[0].1.len()), (una, tcp::URG, 0));
    assert_eq!((s[1].0.seq, s[1].1.len()), (una.wrapping_sub(1), 0));
}

/// La fenêtre s'est ouverte de moins qu'un segment : la sonde emporte ce qui tient. Ce n'est plus
/// une sonde : le recul retombe, et c'est le RTO qui veille (`tcp_send_probe0`).
#[test]
fn sonde_qui_emporte_des_donnees() {
    let (mut c, mut f) = fenetre_fermee(32 * 1024);
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    let una = s[0].0.seq.wrapping_add(1);
    echeance_suivante(&mut c);
    sortants(&mut c);
    let i = c.info(maintenant());
    assert_eq!((i.sondes, i.recul), (2, 2));
    // Un ACK ouvre la fenêtre, de moins d'un segment : elle n'a de sens que multipliée par l'échelle.
    let mut h = sortants_de_fille(&mut f, &mut c);
    h.ack = una;
    h.fenetre = 1;
    c.recevoir(&h, vide(), maintenant());
    assert_eq!(c.info(maintenant()).snd_wnd, 1 << ECHELLE);
    assert!(sortants(&mut c).is_empty());
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    assert_eq!((s.len(), s[0].1.len()), (1, 1 << ECHELLE));
    let i = c.info(maintenant());
    assert_eq!((i.sondes, i.recul, i.non_acquittes), (0, 0, 1));
}

// --- TCP_DEFER_ACCEPT ---

/// Une fille d'une écoute avec TCP_DEFER_ACCEPT `defer`, et le client qui lui répond. Rend
/// le client, la fille, et le dernier ACK du client.
fn fille_differee(defer: u32) -> (Connexion, Connexion, Tcp) {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    f.reglages.defer_accept = defer;
    let synack = sortants(&mut f)[0].0;
    c.recevoir(&synack, vide(), maintenant());
    let ack = sortants(&mut c)[0].0;
    (c, f, ack)
}

/// L'ACK nu de la poignée de main ne fait pas naître la connexion ; les premières données,
/// si (`tcp_check_req`).
#[test]
fn defer_accept_les_donnees_font_naitre() {
    let (mut c, mut f, ack) = fille_differee(1);
    f.recevoir(&ack, vide(), maintenant());
    assert_eq!(f.etat(), Etat::SynRecu);
    assert!(sortants(&mut f).is_empty());
    ecrire(&mut c, b"bonjour");
    let s = sortants(&mut c);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    assert_eq!(f.etat(), Etat::Etablie);
    assert_eq!(lire(&mut f, 100), b"bonjour");
}

/// Les instants, mesurés sur Linux : `defer` = 1 : à 1 s, le SYN-ACK repart (la dernière
/// période), et l'ACK redit fait naître la fille. `defer` = 2 : à 1 s, rien ne repart ; à 3 s,
/// le SYN-ACK : un seul renvoi. (`syn_ack_recalc`.)
#[test]
fn defer_accept_les_instants() {
    for (defer, instants) in [(1u32, &[1000u64][..]), (2, &[1000, 3000])] {
        let t0 = maintenant();
        let (mut c, mut f, ack) = fille_differee(defer);
        f.recevoir(&ack, vide(), maintenant());
        let mut renvois = 0;
        for (k, &t) in instants.iter().enumerate() {
            assert_eq!(f.echeance(), Some(t0 + t * MS), "defer {defer}, echeance {k}");
            avancer(t0 + t * MS - maintenant());
            f.minuteur(maintenant());
            let s = sortants(&mut f);
            renvois += s.len();
            if k + 1 == instants.len() {
                assert_eq!(s.len(), 1, "defer {defer} : le dernier");
                assert_eq!(s[0].0.drapeaux, tcp::SYN | tcp::ACK);
                c.recevoir(&s[0].0, vide(), maintenant());
                for (a, _) in sortants(&mut c) {
                    f.recevoir(&a, vide(), maintenant());
                }
            } else {
                assert!(s.is_empty());
            }
        }
        assert_eq!(renvois, 1);
        assert_eq!(f.etat(), Etat::Etablie);
        assert_eq!(f.info(maintenant()).total_retrans, 1);
    }
}

/// Le client se tait toujours : la fille meurt après `max(tcp_synack_retries, defer)`
/// échéances, sans réponse : 5 SYN-ACK sans TCP_DEFER_ACCEPT ; avec, moins de renvois, car
/// son ACK est arrivé (`syn_ack_recalc`). Et une fille ne perd jamais de fenêtre.
#[test]
fn fille_qui_meurt_en_silence() {
    let f0 = maintenant();
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    sortants(&mut f);
    let mut n = 0;
    while f.etat() != Etat::Fermee {
        echeance_suivante(&mut f);
        n += sortants(&mut f).len();
    }
    assert_eq!((n, (maintenant() - f0) / MS), (5, 63_000));
    assert_eq!(f.congestion().1, SEUIL_INFINI);
    // Avec TCP_DEFER_ACCEPT 10 : ni renvoi jusqu'à la 9e période ; elle meurt après la 10e.
    let (_c, mut f, ack) = fille_differee(10);
    f.recevoir(&ack, vide(), maintenant());
    let mut n = 0;
    let mut tours = 0;
    while f.etat() != Etat::Fermee {
        echeance_suivante(&mut f);
        n += sortants(&mut f).len();
        tours += 1;
    }
    assert_eq!((n, tours), (1, 11));
}

/// `reqsk_timer_handler` : la file à moitié pleine retire des essais, jusqu'à 2 ; TCP_SYNCNT
/// en sert de départ, et un départ de 1 y reste.
#[test]
fn essais_des_filles_sous_la_charge() {
    use inet::tcp::essais_de_filles as essais;
    // Moins de la moitié de la file (et jamais sous 8) : rien ne change.
    assert_eq!(essais(0, 4, 0, 8), 5);
    assert_eq!(essais(0, 4, 0, 4), 5);
    assert_eq!(essais(0, 50, 0, 128), 5);
    // Aucune jeune : tout y passe, jusqu'à 2.
    assert_eq!(essais(0, 100, 0, 128), 2);
    // Toutes jeunes : rien (qlen < 2 x jeunes).
    assert_eq!(essais(0, 100, 100, 128), 5);
    // Une jeune sur deux : qlen = 2 x jeunes : 2 x jeunes, puis 4 x jeunes : un essai de moins.
    assert_eq!(essais(0, 100, 50, 128), 4);
    // Une sur quatre, une sur huit : deux, trois de moins.
    assert_eq!(essais(0, 100, 25, 128), 3);
    assert_eq!(essais(0, 100, 12, 128), 2);
    // TCP_SYNCNT.
    assert_eq!(essais(1, 100, 0, 128), 1);
    assert_eq!(essais(2, 100, 0, 128), 2);
    assert_eq!(essais(10, 100, 50, 128), 9);
    assert_eq!(essais(10, 100, 0, 128), 2);
    assert_eq!(essais(255, 4000, 0, 4096), 2);
}

/// Le client : l'ACK de la poignée de main attend s'il va porter des données : TCP_DEFER_ACCEPT,
/// ou un programme qui attend d'écrire, au plus 200 ms.
#[test]
fn le_client_retient_son_ack() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.ecrivains_en_attente = 1;
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    let s = sortants(&mut f)[0].0;
    c.recevoir(&s, vide(), maintenant());
    assert_eq!(c.etat(), Etat::Etablie);
    assert!(sortants(&mut c).is_empty());
    assert_eq!(c.echeance(), Some(maintenant() + 200 * MS));
    // Les données le portent.
    ecrire(&mut c, b"a");
    let d = sortants(&mut c);
    assert_eq!((d.len(), d[0].0.drapeaux & tcp::ACK), (1, tcp::ACK));
    f.recevoir(&d[0].0, Octets(d[0].1.clone(), 0), maintenant());
    assert_eq!(f.etat(), Etat::Etablie);
}

// --- TCP_INFO : les compteurs, le débit livré, les chronomètres (debit.rs) ---

/// Une conversation comptée ; `linux/tcp.c` compte la même sur le vrai Linux.
#[test]
fn info_les_compteurs() {
    let (mut c, mut f) = paire();
    let (i, j) = (c.info(maintenant()), f.info(maintenant()));
    // Le SYN-ACK de la fille ne compte pas : chez Linux, il part d'une simple demande.
    assert_eq!((i.segs_out, i.segs_in, j.segs_out, j.segs_in), (2, 1, 0, 2));
    assert_eq!((i.livres, j.livres, i.octets_acquittes, j.octets_acquittes), (1, 1, 1, 0));
    assert_eq!((j.rto_reprises, j.rto_temps), (0, 0));
    assert_eq!((i.debit, i.debit_limite, j.debit, j.debit_limite), (0, true, 0, true));
    ecrire(&mut c, &[0; 1000]);
    livrer(&mut c, &mut f);
    assert_eq!(livrer(&mut f, &mut c), 1);
    let (i, j) = (c.info(maintenant()), f.info(maintenant()));
    assert_eq!((i.segs_out, i.data_segs_out, i.octets_envoyes, i.octets_acquittes, i.segs_in, i.data_segs_in), (3, 1, 1000, 1001, 2, 0));
    assert_eq!((j.segs_out, j.data_segs_out, j.segs_in, j.data_segs_in, j.octets_recus), (1, 0, 3, 1, 1000));
    assert_eq!(i.livres, 2);
    // TCP_CORK : ce qui attend.
    c.reglages.cork = true;
    ecrire(&mut c, &[0; 10]);
    sortants(&mut c);
    assert_eq!(c.info(maintenant()).non_envoyes, 10);
    c.reglages.cork = false;
    livrer(&mut c, &mut f);
    assert_eq!(c.info(maintenant()).non_envoyes, 0);
    // Le FIN compte dans ce qui est reçu.
    c.fermer_envoi();
    livrer(&mut c, &mut f);
    assert_eq!(f.info(maintenant()).octets_recus, 1011);
}

/// Les segments rangés hors d'ordre.
#[test]
fn info_hors_ordre() {
    let (mut c, mut f) = paire();
    ecrire(&mut c, &[0; 3 * MSS as usize]);
    let s = sortants(&mut c);
    f.recevoir(&s[1].0, Octets(s[1].1.clone(), 0), maintenant());
    f.recevoir(&s[2].0, Octets(s[2].1.clone(), 0), maintenant());
    assert_eq!(f.info(maintenant()).hors_ordre, 2);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    assert_eq!(f.info(maintenant()).hors_ordre, 2);
}

/// `octets` envoyés à `f`, et leur ACK `ms` plus tard.
fn envoyer_et_acquitter(c: &mut Connexion, f: &mut Connexion, octets: usize, ms: u64) {
    assert_eq!(ecrire(c, &vec![0u8; octets]), octets);
    f.quickack(true);
    livrer(c, f);
    avancer(ms * MS);
    assert!(livrer(f, c) >= 1);
}

/// Le débit livré, à la main (`tcp_rate_gen`) : un aller-retour de 10 ms pour le SYN ; le
/// dernier échantillon s'il n'est pas limité par le programme, sinon le plus haut.
#[test]
fn debit_livre() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    let sa = sortants(&mut f)[0].0;
    avancer(10 * MS);
    c.recevoir(&sa, vide(), maintenant());
    livrer(&mut c, &mut f);
    let mss = c.info(maintenant()).snd_mss as usize;
    let debit = |c: &Connexion| {
        let i = c.info(maintenant());
        (i.debit / mss as u64, i.debit_limite)
    };
    assert_eq!(debit(&c), (0, true));
    // 5 segments en 20 ms : 250 par seconde.
    envoyer_et_acquitter(&mut c, &mut f, 5 * mss, 20);
    assert_eq!(debit(&c), (250, false));
    // Le programme s'est fait attendre, et 1 segment en 40 ms est plus lent : il ne compte pas.
    c.verifier_app_limite(0);
    envoyer_et_acquitter(&mut c, &mut f, mss, 40);
    assert_eq!(debit(&c), (250, false));
    // Limité aussi, mais plus haut que ce qu'on savait : retenu, et dit limité.
    c.verifier_app_limite(0);
    envoyer_et_acquitter(&mut c, &mut f, 10 * mss, 20);
    assert_eq!(debit(&c), (500, true));
    // Limité, plus bas : non (la comparaison : 2 en 20 ms, contre 10 en 20 ms).
    c.verifier_app_limite(0);
    envoyer_et_acquitter(&mut c, &mut f, 2 * mss, 20);
    assert_eq!(debit(&c), (500, true));
    // Pas limité : retenu, même plus bas.
    envoyer_et_acquitter(&mut c, &mut f, 2 * mss, 40);
    assert_eq!(debit(&c), (50, false));
    // Un aller-retour égal au plus petit RTT : un échantillon comme un autre.
    envoyer_et_acquitter(&mut c, &mut f, mss, 10);
    assert_eq!(debit(&c), (100, false));
    // Encore en attente dans la carte : ce n'est pas le programme.
    c.verifier_app_limite(1);
    envoyer_et_acquitter(&mut c, &mut f, mss, 40);
    assert_eq!(debit(&c), (25, false));
}

/// Rien de mesurable : pas de débit (et pas de division par zéro) : l'horloge n'a pas bougé.
#[test]
fn debit_sans_temps() {
    let (mut c, mut f) = paire();
    envoyer_et_acquitter(&mut c, &mut f, 1000, 0);
    assert_eq!(c.info(maintenant()).debit, 0);
}

/// Une connexion établie, avec SACK, de 10 ms d'aller-retour : le client, sa fille, et son MSS.
fn paire_mesuree() -> (Connexion, Connexion, usize) {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.proposer_sack();
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    f.proposer_sack();
    let sa = sortants(&mut f)[0].0;
    avancer(10 * MS);
    c.recevoir(&sa, vide(), maintenant());
    livrer(&mut c, &mut f);
    f.quickack(true);
    let mss = c.info(maintenant()).snd_mss as usize;
    (c, f, mss)
}

/// Un segment vieux, le premier que couvre cet ACK : c'est lui l'échantillon, même s'il est parti
/// avant le dernier acquitté (`!rs->prior_delivered`).
#[test]
fn debit_du_plus_vieux_quand_il_est_seul() {
    let (mut c, mut f, mss) = paire_mesuree();
    let un = mss as u64 * 1_000_000;
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    let s1 = sortants(&mut c);
    avancer(10 * MS);
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    let s2 = sortants(&mut c);
    assert_eq!((s1.len(), s2.len()), (1, 1));
    // Le second d'abord, SACKé : 1 segment, en 30 ms depuis la dernière livraison.
    avancer(20 * MS);
    f.recevoir(&s2[0].0, Octets(s2[0].1.clone(), 0), maintenant());
    assert_eq!(livrer(&mut f, &mut c), 1);
    assert_eq!(c.info(maintenant()).debit, un / 30_000);
    // Le premier : 2 segments en 40 ms.
    avancer(10 * MS);
    f.recevoir(&s1[0].0, Octets(s1[0].1.clone(), 0), maintenant());
    assert_eq!(livrer(&mut f, &mut c), 1);
    assert_eq!(c.info(maintenant()).debit, 2 * un / 40_000);
}

/// Une livraison déplace le départ des mesures (`delivered_mstamp`) : ce qui part ensuite compte de
/// là, pas de plus loin.
#[test]
fn debit_depuis_la_derniere_livraison() {
    let (mut c, mut f, mss) = paire_mesuree();
    let un = mss as u64 * 1_000_000;
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    let s1 = sortants(&mut c);
    avancer(5 * MS);
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    let s2 = sortants(&mut c);
    avancer(10 * MS);
    f.recevoir(&s1[0].0, Octets(s1[0].1.clone(), 0), maintenant());
    assert_eq!(livrer(&mut f, &mut c), 1);
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    let s3 = sortants(&mut c);
    avancer(20 * MS);
    f.recevoir(&s2[0].0, Octets(s2[0].1.clone(), 0), maintenant());
    f.recevoir(&s3[0].0, Octets(s3[0].1.clone(), 0), maintenant());
    assert_eq!(livrer(&mut f, &mut c), 1);
    // s3 : 2 segments de plus, en 20 ms depuis la livraison de s1.
    assert_eq!(c.info(maintenant()).debit, 2 * un / 20_000);
}

/// La bulle du programme court tant que ce qui était en vol n'est pas livré (`app_limited`), et ce
/// qui part pendant ce temps est dit limité.
#[test]
fn la_bulle_du_programme() {
    let (mut c, mut f, mss) = paire_mesuree();
    // Un premier échantillon, pas limité, à battre : 10 par seconde... un seul segment en 100 ms.
    envoyer_et_acquitter(&mut c, &mut f, mss, 100);
    assert_eq!(c.info(maintenant()).debit_limite, false);
    // A en vol ; le programme se fait attendre : la bulle va jusqu'à A.
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    let a = sortants(&mut c);
    c.verifier_app_limite(0);
    // B part pendant la bulle ; A est livré : il ne la dépasse pas : C aussi est limité.
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    let b = sortants(&mut c);
    avancer(100 * MS);
    f.recevoir(&a[0].0, Octets(a[0].1.clone(), 0), maintenant());
    assert_eq!(livrer(&mut f, &mut c), 1);
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    let d = sortants(&mut c);
    // B puis C, lents : limités, plus lents que ce qu'on sait : le débit ne change pas.
    let avant = c.info(maintenant()).debit;
    avancer(400 * MS);
    f.recevoir(&b[0].0, Octets(b[0].1.clone(), 0), maintenant());
    f.recevoir(&d[0].0, Octets(d[0].1.clone(), 0), maintenant());
    assert_eq!(livrer(&mut f, &mut c), 1);
    let i = c.info(maintenant());
    assert_eq!((i.debit, i.debit_limite), (avant, false));
}

/// Ce qui ne fait pas une bulle : autant qu'un segment qui attend, ou la cwnd pleine.
#[test]
fn pas_de_bulle() {
    let (mut c, mut f, mss) = paire_mesuree();
    envoyer_et_acquitter(&mut c, &mut f, mss, 10);
    // Ce qui suit, s'il n'y a pas de bulle, est retenu, même plus lent : 1 par seconde.
    let lent = |c: &mut Connexion, f: &mut Connexion| {
        envoyer_et_acquitter(c, f, mss, 1000);
        let i = c.info(maintenant());
        assert_eq!((i.debit / mss as u64, i.debit_limite), (1, false));
    };
    let tout_acquitter = |c: &mut Connexion, f: &mut Connexion, s: Vec<(Tcp, Vec<u8>)>| {
        avancer(10 * MS);
        for (h, o) in s {
            f.recevoir(&h, Octets(o, 0), maintenant());
        }
        assert!(livrer(f, c) >= 1);
        assert_eq!(c.info(maintenant()).non_acquittes, 0);
    };
    // Un segment entier qui attend.
    c.reglages.cork = true;
    assert_eq!(ecrire(&mut c, &vec![0u8; mss]), mss);
    c.verifier_app_limite(0);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 1);
    c.reglages.cork = false;
    tout_acquitter(&mut c, &mut f, s);
    lent(&mut c, &mut f);
    // La cwnd pleine.
    let cwnd = c.info(maintenant()).cwnd as usize;
    assert_eq!(ecrire(&mut c, &vec![0u8; cwnd * mss]), cwnd * mss);
    let s = sortants(&mut c);
    assert_eq!(s.len(), cwnd);
    c.verifier_app_limite(0);
    tout_acquitter(&mut c, &mut f, s);
    lent(&mut c, &mut f);
    // Encore dans la carte.
    c.verifier_app_limite(1);
    lent(&mut c, &mut f);
}

/// Un segment SACKé n'est compté qu'une fois : l'ACK cumulatif qui le couvre ensuite garde,
/// parmi les autres, le plus récent (`tcp_rate_skb_delivered`).
#[test]
fn debit_livre_avec_sack() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.proposer_sack();
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    f.proposer_sack();
    let sa = sortants(&mut f)[0].0;
    avancer(10 * MS);
    c.recevoir(&sa, vide(), maintenant());
    livrer(&mut c, &mut f);
    let mss = c.info(maintenant()).snd_mss as usize;
    assert_eq!(ecrire(&mut c, &vec![0u8; 3 * mss]), 3 * mss);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 3);
    f.recevoir(&s[2].0, Octets(s[2].1.clone(), 0), maintenant());
    avancer(30 * MS);
    assert_eq!(livrer(&mut f, &mut c), 1);
    let i = c.info(maintenant());
    assert_eq!((i.livres, i.debit), (2, mss as u64 * 1_000_000 / 30_000));
    avancer(10 * MS);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    f.recevoir(&s[1].0, Octets(s[1].1.clone(), 0), maintenant());
    assert_eq!(livrer(&mut f, &mut c), 1);
    let i = c.info(maintenant());
    assert_eq!((i.livres, i.debit), (4, 3 * mss as u64 * 1_000_000 / 40_000));
}

/// Le temps occupé : tant que quelque chose attend, d'être envoyé ou acquitté.
#[test]
fn chronos_occupee() {
    let (mut c, mut f) = paire();
    assert_eq!(c.info(maintenant()).occupe, 0);
    ecrire(&mut c, &[0; 5 * 1000]);
    f.quickack(true);
    livrer(&mut c, &mut f);
    avancer(20 * MS);
    assert_eq!(c.info(maintenant()).occupe, 20_000);
    assert!(livrer(&mut f, &mut c) >= 1);
    avancer(20 * MS);
    let i = c.info(maintenant());
    assert_eq!((i.occupe, i.fenetre_limitee, i.tampon_limite), (20_000, 0, 0));
}

/// La fenêtre de l'autre : le temps passe à son compte, jusqu'à ce qu'elle s'ouvre.
#[test]
fn chronos_fenetre_de_l_autre() {
    let (mut c, mut f) = paire_avec(MSS, 8192, 262_144);
    assert_eq!(ecrire(&mut c, &vec![0u8; 64 * 1024]), 64 * 1024);
    calmer(&mut c, &mut f);
    assert!(c.info(maintenant()).non_envoyes > 0);
    let avant = c.info(maintenant());
    avancer(40 * MS);
    let i = c.info(maintenant());
    assert_eq!(i.fenetre_limitee - avant.fenetre_limitee, 40_000);
    assert_eq!(i.occupe - avant.occupe, 40_000);
    // L'autre lit : elle s'ouvre, et ce n'est plus sa faute.
    while !lire(&mut f, 1 << 20).is_empty() {
        calmer(&mut c, &mut f);
    }
    let avant = c.info(maintenant());
    avancer(40 * MS);
    assert_eq!(c.info(maintenant()).fenetre_limitee, avant.fenetre_limitee);
}

/// Elle s'ouvre, et il reste de quoi envoyer (ici, retenu par TCP_CORK) : la connexion reste occupée,
/// mais plus à cause de la fenêtre (`tcp_chrono_stop`).
#[test]
fn chronos_fenetre_qui_s_ouvre_en_restant_occupee() {
    let (mut c, mut f) = paire_avec(MSS, 8192, 262_144);
    c.reglages.cork = true;
    let octets = 16 * MSS as usize + 100;
    assert_eq!(ecrire(&mut c, &vec![0u8; octets]), octets);
    calmer(&mut c, &mut f);
    avancer(8 * MS);
    let i = c.info(maintenant());
    assert!(i.fenetre_limitee >= 8000, "{}", i.fenetre_limitee);
    while !lire(&mut f, 1 << 20).is_empty() {
        calmer(&mut c, &mut f);
    }
    assert_eq!(c.info(maintenant()).non_envoyes, 100);
    let avant = c.info(maintenant());
    avancer(40 * MS);
    let i = c.info(maintenant());
    assert_eq!(i.fenetre_limitee, avant.fenetre_limitee);
    assert_eq!(i.occupe - avant.occupe, 40_000);
}

/// Le tampon du programme : tout est parti, sans que la cwnd n'y soit pour rien, et il attend de
/// la place : c'est lui qui limite (`tcp_cwnd_validate`). Jusqu'à ce que la place revienne.
#[test]
fn chronos_tampon_plein() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 8192, ECHELLE);
    c.sndbuf_fixe = true;
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    calmer(&mut c, &mut f);
    assert_eq!(ecrire(&mut c, &[0; 6000]), 6000);
    c.marquer_sans_place();
    f.quickack(true);
    livrer(&mut c, &mut f);
    avancer(8 * MS);
    let i = c.info(maintenant());
    assert_eq!((i.tampon_limite, i.occupe), (8000, 8000));
    assert!(livrer(&mut f, &mut c) >= 1);
    avancer(8 * MS);
    assert_eq!(c.info(maintenant()).tampon_limite, 8000);
}

/// Les épisodes de RTO : un seul pour des RTO de suite, son temps court jusqu'à la sortie de
/// l'état de perte, puis reste.
#[test]
fn info_rto() {
    let (mut c, mut f) = paire();
    ecrire(&mut c, &[0; 1000]);
    sortants(&mut c);
    echeance_suivante(&mut c);
    sortants(&mut c);
    let i = c.info(maintenant());
    assert_eq!((i.total_rto, i.rto_reprises, i.rto_temps), (1, 1, 0));
    avancer(50 * MS);
    assert_eq!(c.info(maintenant()).rto_temps, 50);
    let debut = maintenant() - 50 * MS;
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 1);
    let i = c.info(maintenant());
    assert_eq!((i.total_rto, i.rto_reprises), (2, 1));
    assert_eq!(i.rto_temps as u64, (maintenant() - debut) / MS);
    assert_eq!((i.octets_envoyes, i.octets_renvoyes, i.data_segs_out), (3000, 2000, 3));
    f.quickack(true);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    assert_eq!(livrer(&mut f, &mut c), 1);
    // Sans SACK, l'état de perte attend un ACK au-delà de `high_seq`
    // (`tcp_try_undo_recovery`) : le temps court encore.
    avancer(10 * MS);
    assert_eq!(c.info(maintenant()).rto_temps as u64, (maintenant() - debut) / MS);
    envoyer_et_acquitter(&mut c, &mut f, 1000, 0);
    let fin = c.info(maintenant()).rto_temps;
    assert_eq!(fin as u64, (maintenant() - debut) / MS);
    avancer(50 * MS);
    assert_eq!(c.info(maintenant()).rto_temps, fin);
}

/// Ce que les RTO de ses SYN-ACK laissent à la fille (`tcp_create_openreq_child`).
#[test]
fn info_rto_d_une_fille() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    let sa = sortants(&mut f)[0].0;
    c.recevoir(&sa, vide(), maintenant());
    let ack = sortants(&mut c)[0].0;
    echeance_suivante(&mut f);
    assert_eq!(sortants(&mut f).len(), 1);
    f.recevoir(&ack, vide(), maintenant());
    assert_eq!(f.etat(), Etat::Etablie);
    let i = f.info(maintenant());
    assert_eq!((i.total_rto, i.rto_reprises, i.rto_temps), (1, 1, 1000));
    assert_eq!((i.segs_in, i.segs_out, i.total_retrans), (2, 0, 1));
}

// --- La MTU du chemin (`tcp_v4_mtu_reduced`) ---

/// Une « fragmentation nécessaire » : le MSS baisse (les horodatages comptés : 1000 - 40 -
/// 12 = 948, mesuré), et ce qui est en vol et trop long repart tout de suite, découpé, sans
/// toucher à la cwnd, en Perte. Ce qui repart couvre tout, sans rien de neuf.
#[test]
fn mtu_reduite_redecoupe_ce_qui_est_en_vol() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 1 << 20, ECHELLE);
    c.proposer_horodatages(1);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 1 << 20, ECHELLE);
    f.decalage_horodatages(2);
    calmer(&mut c, &mut f);
    let mss_avant = c.mss() as usize;
    assert_eq!(mss_avant, MSS as usize - 12);
    ecrire(&mut c, &vec![1u8; 3 * mss_avant]);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 3);
    let (una, nxt, _) = c.numeros();
    let cwnd = c.congestion().0;
    assert!(c.mtu_reduite(1000, 1000, true, true).a_emettre);
    assert_eq!(c.mss(), 948);
    assert_eq!(c.info(maintenant()).pmtu, 1000);
    let i = c.info(maintenant());
    assert_eq!((i.phase, i.perdus, i.cwnd), (4, 3, cwnd));
    let r = sortants(&mut c);
    assert!(r.len() >= 3 && r.iter().all(|(_, o)| o.len() <= 948), "{:?}", r.iter().map(|(_, o)| o.len()).collect::<Vec<_>>());
    assert_eq!(r[0].0.seq, una);
    assert_eq!(c.numeros().1, nxt, "SND.NXT ne bouge pas");
    assert_eq!(c.erreur(), 0);
    // Sous le plancher (dit 400, retenu 552) et DF : l'erreur douce, sans plus.
    assert!(!c.mtu_reduite(400, 1000, true, true).a_emettre);
    assert_eq!(c.erreur_douce(), t::EMSGSIZE);
    // IP_PMTUDISC_DONT : rien ne change, le RTO s'en occupera.
    let (mut c, _f) = paire();
    ecrire(&mut c, &vec![1u8; MSS as usize]);
    sortants(&mut c);
    assert!(!c.mtu_reduite(1000, 1000, false, false).a_emettre);
    assert_eq!(c.mss(), MSS);
    // Plus haut que ce qu'on suppose : rien.
    assert!(!c.mtu_reduite(2000, 2000, true, true).a_emettre);
    assert_eq!(c.mss(), MSS);
}

/// La MTU qui remonte (une exception expirée, `tcp_current_mss`) : le MSS suit.
#[test]
fn mtu_qui_remonte() {
    let (mut c, _f) = paire();
    c.mtu_reduite(1000, 1000, true, true);
    assert_eq!(c.mss(), 960);
    c.verifier_mtu(1500);
    assert_eq!(c.mss(), MSS);
    assert_eq!(c.info(maintenant()).pmtu, 1500);
}

// --- TSQ et l'autocork (carte.rs) ---

/// Une connexion par une carte, qui garde `octets` octets et n'a pas encore fini.
fn par_une_carte() -> (Connexion, Connexion) {
    let (mut c, f) = paire_avec(MSS, 1 << 20, 1 << 20);
    c.sans_file = false;
    (c, f)
}

/// L'autocork (`tcp_should_autocork`) : un petit `send` alors que la carte a de quoi
/// s'occuper et que du vol reste : retenu ; le suivant s'y ajoute, et la fin d'émission
/// les envoie ensemble (`tcp_write_xmit`), comme un ACK le ferait. Aucune aide du
/// programme, même sous TCP_NODELAY.
#[test]
fn autocork_retient_les_petits_envois() {
    let (mut c, _f) = par_une_carte();
    let r = t::Reglages { nodelay: true, ..c.reglages };
    c.regler(r, maintenant());
    // Rien en vol : le premier part tout de suite.
    c.poser_en_file(100_000, 0);
    ecrire(&mut c, b"un");
    assert_eq!(sortants(&mut c).len(), 1);
    assert!(!c.prendre_etrangle());
    // La carte le garde encore : les suivants sont retenus.
    c.poser_en_file(100_000, 0);
    ecrire(&mut c, b"deux");
    assert_eq!(sortants(&mut c).len(), 0);
    assert!(c.prendre_etrangle());
    c.poser_en_file(100_000, 0);
    ecrire(&mut c, b"trois");
    assert_eq!(sortants(&mut c).len(), 0);
    assert!(c.prendre_etrangle());
    // La fin d'émission : tout part, en un segment.
    c.poser_en_file(0, 1);
    let s = sortants(&mut c);
    assert_eq!(s.iter().map(|(_, o)| o.as_slice()).collect::<Vec<_>>(), [b"deuxtrois".as_slice()]);
    assert!(!c.prendre_etrangle());
    // Une carte qui a presque tout fini (moins qu'un segment) : pas de retenue.
    c.poser_en_file(10, 2);
    ecrire(&mut c, b"quatre");
    assert_eq!(sortants(&mut c).len(), 1);
    // Par `lo` : jamais.
    let (mut c, _f) = paire_avec(MSS, 1 << 20, 1 << 20);
    let r = t::Reglages { nodelay: true, ..c.reglages };
    c.regler(r, maintenant());
    c.poser_en_file(1 << 20, 0);
    ecrire(&mut c, b"a");
    sortants(&mut c);
    c.poser_en_file(1 << 20, 0);
    ecrire(&mut c, b"b");
    assert_eq!(sortants(&mut c).len(), 1);
}

/// Les blocs d'écriture pleins partent toujours ; seule la queue, en dessous d'un bloc,
/// est retenue.
#[test]
fn autocork_laisse_passer_les_blocs_pleins() {
    let (mut c, _f) = par_une_carte();
    let r = t::Reglages { nodelay: true, ..c.reglages };
    c.regler(r, maintenant());
    grandir_sans_carte(&mut c);
    ecrire(&mut c, b"un");
    assert_eq!(sortants(&mut c).len(), 1);
    c.poser_en_file(100_000, 0);
    // Un bloc fait 44 MSS sur Ethernet (64 Kio moins les en-têtes, le TSO de Linux).
    let bloc = (65_536 - 321) / MSS as usize * MSS as usize;
    ecrire(&mut c, &vec![1u8; bloc + 100]);
    let s = sortants(&mut c);
    assert_eq!(s.iter().map(|(_, o)| o.len()).sum::<usize>(), bloc, "la queue de 100 octets reste");
}

/// `tcp_small_queue_check` : pas plus d'environ 1 ms de débit dans la carte, et jamais
/// plus de 4 Mio : le reste attend la fin d'émission. Toujours un segment s'il est seul
/// en vol.
#[test]
fn tsq_borne_ce_que_garde_la_carte() {
    let (mut c, _f) = par_une_carte();
    grandir_sans_carte(&mut c);
    let cwnd = c.congestion().0 as usize;
    assert!(cwnd > 20);
    ecrire(&mut c, &vec![1u8; cwnd * MSS as usize]);
    c.poser_en_file(5 << 20, 0);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 2, "la carte déborde : le premier, seul en vol, et le suivant : la règle regarde avant d'envoyer");
    assert!(c.prendre_etrangle());
    // La fin d'émission : la suite ; sans doublon.
    c.poser_en_file(0, u64::MAX);
    let s2 = sortants(&mut c);
    assert_eq!(s2.len(), cwnd - 2);
    assert_eq!(s2[0].0.seq, s[1].0.seq.wrapping_add(MSS as u32));
    assert!(!c.prendre_etrangle());
}

/// La cwnd portée à plus de 20 segments, par Reno, la carte vide à chaque tour ; l'ACK de
/// chaque segment vient de la main.
fn grandir_sans_carte(c: &mut Connexion) {
    c.choisir_controle(t::Controle::Reno, maintenant());
    let modele = Tcp { drapeaux: tcp::ACK, seq: c.numeros().2, fenetre: 65_535, ..Tcp::default() };
    for _ in 0..4 {
        let cwnd = c.congestion().0 as usize;
        ecrire(c, &vec![0u8; cwnd * MSS as usize]);
        loop {
            c.poser_en_file(0, u64::MAX);
            let s = sortants(c);
            if s.is_empty() {
                break;
            }
            for (h, o) in &s {
                c.recevoir(&Tcp { ack: h.seq.wrapping_add(o.len() as u32), ..modele }, vide(), maintenant());
            }
        }
    }
    assert_eq!(c.non_acquittes(), 0);
}

/// `skb_still_in_host_queue` : un segment que la carte n'a pas fini n'est pas perdu :
/// le RTO ne le renvoie pas, ne recule pas, et réessaie dans 500 ms ; la sonde de fin de
/// rafale ne le renvoie pas non plus.
#[test]
fn encore_dans_la_carte_pas_de_renvoi() {
    let (mut c, _f) = par_une_carte();
    ecrire(&mut c, &vec![1u8; MSS as usize]);
    c.poser_en_file(0, 0);
    assert_eq!(sortants(&mut c).len(), 1);
    let rto = c.congestion().2;
    let e = c.echeance().unwrap();
    avancer(e.saturating_sub(maintenant()));
    c.minuteur(maintenant());
    c.poser_en_file(5000, 0);
    assert_eq!(sortants(&mut c).len(), 0);
    assert!(c.prendre_etrangle());
    // Le recul vaut quand même (`tcp_retransmit_timer` : -EBUSY n'est pas > 0).
    assert_eq!(c.congestion().2, 2 * rto);
    assert_eq!(c.echeance().unwrap() - maintenant(), 2 * rto);
    // La carte a fini : le prochain essai part.
    avancer(2 * rto);
    c.minuteur(maintenant());
    c.poser_en_file(0, 1);
    assert_eq!(sortants(&mut c).len(), 1);
}

/// La file hors d'ordre est bornée par SO_RCVBUF : un pair qui envoie des milliers de
/// segments d'un octet derrière un trou ne fait pas tout garder. Sans trous entre eux,
/// ils sont fondus en paquets denses (`tcp_collapse_ofo_queue`), et tous gardés ;
/// séparés, au-delà de la limite, jetés par la fin (`tcp_prune_ofo_queue`).
#[test]
fn file_hors_d_ordre_bornee() {
    let (_c, mut f) = paire_avec(MSS, 16_384, 16_384);
    f.rcvbuf_fixe = true;
    let bord = bord(&f);
    let modele = Tcp { drapeaux: tcp::ACK, ack: f.numeros().0, fenetre: 65_535, ..Tcp::default() };
    for i in 1..4000u32 {
        f.recevoir(&Tcp { seq: bord.wrapping_add(i), ..modele }, Octets(vec![1], 0), maintenant());
    }
    assert!(f.memoire_reception() <= 16_384 + 66, "{}", f.memoire_reception());
    f.recevoir(&Tcp { seq: bord, ..modele }, Octets(vec![0], 0), maintenant());
    assert_eq!(f.lisibles(), 4000);
    let (_c, mut f) = paire_avec(MSS, 16_384, 16_384);
    f.rcvbuf_fixe = true;
    let bord = crate::bord(&f);
    let modele = Tcp { drapeaux: tcp::ACK, ack: f.numeros().0, fenetre: 65_535, ..Tcp::default() };
    for i in 1..4000u32 {
        f.recevoir(&Tcp { seq: bord.wrapping_add(2 * i), ..modele }, Octets(vec![1], 0), maintenant());
    }
    assert!(f.memoire_reception() <= 16_384 + 66, "{}", f.memoire_reception());
    f.recevoir(&Tcp { seq: bord, ..modele }, Octets(vec![0], 0), maintenant());
    assert_eq!(f.lisibles(), 1, "le segment qui comble le trou passe toujours");
}

/// Une fenêtre qui se ferme sur des données en vol : le RTO renvoie quand
/// même la tête (`__tcp_retransmit_skb` : SND.UNA part toujours), sinon
/// rien ne repartirait jamais.
#[test]
fn fenetre_refermee_la_tete_repart() {
    let (mut c, _f) = paire();
    ecrire(&mut c, &vec![4u8; 3 * MSS as usize]);
    assert_eq!(sortants(&mut c).len(), 3);
    let una = c.numeros().0;
    c.recevoir(&Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 0, ..Tcp::default() }, vide(), maintenant());
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    assert!(s.iter().any(|(h, o)| h.seq == una && !o.is_empty()), "{:?}", s.iter().map(|(h, o)| (h.seq, o.len())).collect::<Vec<_>>());
}

/// Une fenêtre nulle sur des données en vol, l'autre répondant à chaque
/// essai : jamais d'abandon, même au-delà de `tcp_retries2` (Linux ne
/// compte pas ces RTO comme des échecs tant que l'autre répond).
#[test]
fn fenetre_nulle_en_vol_sans_abandon() {
    let (mut c, _f) = paire();
    ecrire(&mut c, &vec![6u8; MSS as usize]);
    sortants(&mut c);
    let una = c.numeros().0;
    for _ in 0..40 {
        c.recevoir(&Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 0, ..Tcp::default() }, vide(), maintenant());
        echeance_suivante(&mut c);
        sortants(&mut c);
        assert_eq!(c.etat(), Etat::Etablie);
    }
}

/// Un ACK qui avance remet à zéro le compte des retransmissions et leur
/// début (`tcp_ack` : `icsk_retransmits = 0`) : une perte réparée ne
/// rapproche pas l'abandon d'une perte suivante, qui vient toujours
/// 924,6 s après elle (`tcp_retries2`).
#[test]
fn retransmissions_remises_a_zero() {
    let (mut c, mut f) = paire();
    ecrire(&mut c, b"a");
    sortants(&mut c);
    for _ in 0..5 {
        echeance_suivante(&mut c);
        sortants(&mut c);
    }
    echeance_suivante(&mut c);
    livrer(&mut c, &mut f);
    livrer(&mut f, &mut c);
    lire(&mut f, 100);
    calmer(&mut c, &mut f);
    ecrire(&mut c, b"b");
    sortants(&mut c);
    let debut = maintenant();
    while c.etat() != Etat::Fermee {
        echeance_suivante(&mut c);
        sortants(&mut c);
    }
    assert!(maintenant() - debut >= 924_600 * MS, "{} ms", (maintenant() - debut) / MS);
}

/// PRR fait toujours la place de la retransmission rapide en entrant dans
/// la reprise (`tcp_cwnd_reduction` : au moins un segment tant que rien
/// n'est parti), même quand ce qui reste en vol égale déjà le seuil : neuf
/// segments, le premier perdu, trois ACK dupliqués (le premier ACK de
/// l'autre met à jour la fenêtre : il ne compte pas) ; en vol, 9 - 3 - 1 =
/// 5, le seuil 5 ; la cwnd, 6 (Linux : `tcp_packets_in_flight` + 1).
#[test]
fn prr_envoie_la_retransmission_rapide() {
    let (mut c, mut f) = paire();
    // Le seuil de Reno : 5. (CUBIC : 7 : `delta` positif, et la borne n'est jamais atteinte.)
    c.choisir_controle(t::Controle::Reno, maintenant());
    ecrire(&mut c, &vec![0u8; 9 * MSS as usize]);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 9);
    let tete = s[0].0.seq;
    for (h, o) in s.into_iter().skip(1).take(4) {
        f.recevoir(&h, Octets(o, 0), maintenant());
        for (a, _) in sortants(&mut f) {
            c.recevoir(&a, vide(), maintenant());
        }
    }
    assert_eq!(c.congestion().0, 6);
    let r = sortants(&mut c);
    assert!(r.iter().any(|(h, _)| h.seq == tete), "{:?}", r.iter().map(|(h, o)| (h.seq, o.len())).collect::<Vec<_>>());
}

/// Un ACK retardé presque échu (moins d'un quart de l'ato) part tout de
/// suite quand un autre segment arrive, au lieu d'attendre encore
/// (`tcp_send_delayed_ack`).
#[test]
fn ack_retarde_presque_echu() {
    let (mut c, mut f) = paire();
    for _ in 0..16 {
        ecrire(&mut c, b"a");
        livrer(&mut c, &mut f);
        livrer(&mut f, &mut c);
    }
    ecrire(&mut c, b"b");
    let s = sortants(&mut c);
    let (h, o) = s[0].clone();
    f.recevoir(&h, Octets(o, 0), maintenant());
    assert!(sortants(&mut f).is_empty());
    assert_eq!(f.echeance(), Some(maintenant() + 40 * MS));
    avancer(35 * MS);
    let suite = Tcp { seq: h.seq.wrapping_add(1), ..h };
    f.recevoir(&suite, Octets(b"c".to_vec(), 0), maintenant());
    assert_eq!(sortants(&mut f).len(), 1);
}

// --- Le débit et les options (6h, commit 7) ---

#[test]
fn echelle_de_fenetre() {
    // Proposée dans le SYN, rendue dans le SYN-ACK : 7 des deux côtés.
    let mut c = Connexion::connecter(1, 2, 0, 65_000, 1 << 20, 1 << 22, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    assert_eq!(syn.options.echelle, Some(ECHELLE));
    let mut f = Connexion::depuis_syn(&syn, 0, 65_000, 1 << 20, 1 << 22, ECHELLE);
    let synack = sortants(&mut f)[0].0;
    assert_eq!(synack.options.echelle, Some(ECHELLE));
    c.recevoir(&synack, vide(), maintenant());
    livrer(&mut c, &mut f);
    let i = c.info(maintenant());
    assert_eq!((i.options, i.echelle_envoi, i.echelle_reception), (4, 7, 7));
    // La fenêtre d'un SYN n'est jamais décalée : 65 535 au plus, jusqu'au
    // premier segment de l'autre, qui annonce 512 Kio (décalée de 7).
    ecrire(&mut f, b"x");
    calmer(&mut c, &mut f);
    // Alors la première volée (des segments de 65 000 octets, dans la
    // limite de la fenêtre) dépasse 64 Kio.
    ecrire(&mut c, &vec![3u8; 1 << 20]);
    let volee: usize = sortants(&mut c).iter().map(|(_, o)| o.len()).sum();
    assert!(volee > 65_535 && volee <= 1 << 19, "{volee}");
    // Sans l'option dans le SYN de l'autre : pas d'échelle, ni dans le
    // SYN-ACK.
    let nu = Tcp { options: tcp::Options { echelle: None, ..syn.options }, ..syn };
    let mut f = Connexion::depuis_syn(&nu, 0, MSS, 1 << 20, 1 << 22, ECHELLE);
    let synack = sortants(&mut f)[0].0;
    assert_eq!(synack.options.echelle, None);
}

/// L'échelle proposée, comme `tcp_select_initial_window` : d'après la plus
/// grande place de la machine (`tcp_rmem[2]`), ou SO_RCVBUF s'il est fixé
/// (mesuré sous Linux 6.18 : 10 sur une machine de 12 Gio, `tcp_rmem[2]`
/// de 32 Mio ; 7 avec SO_RCVBUF fixé à 8 Mio ; 8 sur la machine de l'étape,
/// 2 Gio). Une échelle de 0 est proposée, et en service ; plus de 14 chez
/// l'autre, 14.
#[test]
fn echelle_comme_linux() {
    assert_eq!(t::echelle(131_072, false, 32 << 20, 0), 10);
    assert_eq!(t::echelle(8 << 20, true, 32 << 20, 0), 7);
    assert_eq!(t::echelle(131_072, false, 15 << 20, 0), 8);
    assert_eq!(t::echelle(4096, true, 32 << 20, 0), 0);
    let mut c = Connexion::connecter(1, 2, 0, MSS, 131_072, 16_384, 0);
    let syn = sortants(&mut c)[0].0;
    assert_eq!(syn.options.echelle, Some(0));
    let quinze = Tcp { options: tcp::Options { echelle: Some(15), ..syn.options }, ..syn };
    let mut f = Connexion::depuis_syn(&quinze, 0, MSS, 131_072, 16_384, ECHELLE);
    let synack = sortants(&mut f)[0].0;
    assert_eq!(synack.options.echelle, Some(ECHELLE));
    c.recevoir(&Tcp { options: tcp::Options { echelle: Some(15), ..synack.options }, ..synack }, vide(), maintenant());
    let i = c.info(maintenant());
    assert_eq!((i.options, i.echelle_envoi, i.echelle_reception), (4, 14, 0));
}

#[test]
fn nagle_et_minshall() {
    let (mut c, mut f) = paire();
    // Un petit segment part ; le suivant attend son ACK.
    ecrire(&mut c, b"a");
    let mut en_route = sortants(&mut c);
    assert_eq!(en_route.len(), 1);
    ecrire(&mut c, b"b");
    assert!(sortants(&mut c).is_empty());
    // Un segment plein part quand même (Minshall : seul le petit attend).
    ecrire(&mut c, &vec![9u8; MSS as usize + 9]);
    let s = sortants(&mut c);
    assert_eq!(s.iter().map(|(_, o)| o.len()).collect::<Vec<_>>(), vec![MSS as usize]);
    en_route.extend(s);
    // Ils arrivent, leur ACK revient : le reste part.
    for (h, o) in en_route {
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    calmer(&mut c, &mut f);
    assert_eq!(c.non_acquittes(), 0);
    assert_eq!(f.lisibles(), 2 + MSS as usize + 9);
    // TCP_NODELAY : pas d'attente.
    let r = t::Reglages { nodelay: true, ..c.reglages };
    c.regler(r, maintenant());
    ecrire(&mut c, b"x");
    ecrire(&mut c, b"y");
    assert_eq!(sortants(&mut c).len(), 1);
    ecrire(&mut c, b"z");
    assert_eq!(sortants(&mut c).len(), 1);
}

#[test]
fn tcp_cork_et_msg_more() {
    let (mut c, mut f) = paire();
    // TCP_CORK : un segment incomplet attend, même sans rien en vol ; la
    // sonde le pousse au bout d'un RTO (200 ms).
    let r = t::Reglages { cork: true, ..c.reglages };
    c.regler(r, maintenant());
    ecrire(&mut c, b"bouchon");
    assert!(sortants(&mut c).is_empty());
    let avant = maintenant();
    echeance_suivante(&mut c);
    assert_eq!((maintenant() - avant) / MS, 200);
    let s = sortants(&mut c);
    assert_eq!(&s[0].1[..], b"bouchon");
    for (h, o) in s {
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    calmer(&mut c, &mut f);
    // Un segment plein part ; le bouchon retiré pousse le reste.
    ecrire(&mut c, &vec![1u8; MSS as usize + 5]);
    let s = sortants(&mut c);
    assert_eq!(s.len(), 1);
    for (h, o) in s {
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    let r = t::Reglages { cork: false, ..c.reglages };
    let e = c.regler(r, maintenant());
    assert!(e.a_emettre);
    let s = sortants(&mut c);
    assert_eq!(s[0].1.len(), 5);
    for (h, o) in s {
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    calmer(&mut c, &mut f);
    // MSG_MORE : seulement pour l'écriture qui le dit.
    ecrire(&mut c, b"debut");
    c.plus_a_venir = true;
    assert!(sortants(&mut c).is_empty());
    ecrire(&mut c, b" et fin");
    assert_eq!(&sortants(&mut c)[0].1[..], b"debut et fin");
}

#[test]
fn keepalive() {
    let (mut c, mut f) = paire();
    let r = t::Reglages { keepalive: true, keepidle: 1000 * MS, keepintvl: 500 * MS, keepcnt: 3, ..c.reglages };
    c.regler(r, maintenant());
    let debut = maintenant();
    // Une sonde après une seconde de silence, d'un numéro déjà acquitté ;
    // l'autre répond, et le silence recommence.
    echeance_suivante(&mut c);
    assert_eq!((maintenant() - debut) / MS, 1000);
    let s = sortants(&mut c);
    assert_eq!((s.len(), s[0].0.seq, s[0].1.len()), (1, c.numeros().0.wrapping_sub(1), 0));
    f.recevoir(&s[0].0, vide(), maintenant());
    let r = sortants(&mut f);
    assert_eq!(r.len(), 1);
    c.recevoir(&r[0].0, vide(), maintenant());
    // Puis l'autre se tait : trois sondes, à 500 ms d'intervalle, puis RST
    // et ETIMEDOUT.
    let t1 = maintenant();
    let mut sondes = 0;
    while c.etat() != Etat::Fermee {
        echeance_suivante(&mut c);
        for (h, _) in sortants(&mut c) {
            if h.drapeaux & tcp::RST != 0 {
                assert_eq!((maintenant() - t1) / MS, 2500);
            } else {
                sondes += 1;
            }
        }
    }
    assert_eq!((sondes, c.prendre_erreur()), (3, t::ETIMEDOUT));
}

#[test]
fn octet_urgent() {
    let (mut c, mut f) = paire();
    // send("abc", MSG_OOB) : « c » est urgent, le pointeur le suit.
    ecrire(&mut c, b"abc");
    c.marquer_urgent();
    let s = sortants(&mut c);
    assert_eq!((s[0].0.drapeaux & tcp::URG, s[0].0.urgent), (tcp::URG, 3));
    for (h, o) in s {
        f.recevoir(&h, Octets(o, 0), maintenant());
    }
    assert!(f.urgent_a_lire());
    // La lecture s'arrête à la marque ; MSG_OOB lit l'octet urgent ; la
    // lecture suivante le saute.
    assert_eq!(lire(&mut f, 100), b"ab");
    assert!(f.a_la_marque());
    assert_eq!(f.lire_urgent(true), Ok(Some(b'c')));
    assert_eq!(f.lire_urgent(false), Ok(Some(b'c')));
    assert_eq!(f.lire_urgent(false), Err(t::EINVAL));
    ecrire(&mut c, b"de");
    calmer(&mut c, &mut f);
    assert_eq!(lire(&mut f, 100), b"de");
    assert!(!f.a_la_marque());
    // Plus de mode urgent : plus de pointeur.
    ecrire(&mut c, b"f");
    assert_eq!(sortants(&mut c)[0].0.drapeaux & tcp::URG, 0);
    // SO_OOBINLINE : l'octet reste dans le flux.
    let (mut c, mut f) = paire();
    let r = t::Reglages { oobinline: true, ..f.reglages };
    f.regler(r, maintenant());
    ecrire(&mut c, b"xy");
    c.marquer_urgent();
    calmer(&mut c, &mut f);
    assert_eq!(f.lire_urgent(false), Err(t::EINVAL));
    assert_eq!(lire(&mut f, 100), b"x");
    assert_eq!(lire(&mut f, 100), b"y");
}

#[test]
fn so_sndbuf_agrandi() {
    // Deux fenêtres de dix segments, chacun compté avec sa place en
    // mémoire : MSS 1460 → 2 × 10 × (4096 + 256).
    let (c, _) = paire_avec(1460, 131_072, 16_384);
    assert_eq!(c.sndbuf, 87_040);
    // Sur lo (MSS 65 495) : 2 626 560, ce que mesure Linux.
    let (c, _) = paire_avec(65_495, 131_072, 16_384);
    assert_eq!(c.sndbuf, 2_626_560);
    // SO_SNDBUF fixé par le programme : il ne bouge plus.
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.sndbuf_fixe = true;
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    calmer(&mut c, &mut f);
    assert_eq!(c.sndbuf, 16_384);
}

/// TCP_INFO sans connexion, et d'une écoute : ce qu'en rend Linux (mesuré).
#[test]
fn info_sans_connexion() {
    let i = t::Info::sans_connexion();
    assert_eq!((i.etat, i.rto, i.snd_mss, i.rttvar, i.ssthresh, i.cwnd, i.reordonnancement, i.min_rtt, i.pacing), (7, 1_000_000, 536, 250_000, SEUIL_INFINI, 10, 3, u32::MAX, u64::MAX));
    let i = t::Info::ecoute(1, 7);
    assert_eq!((i.etat, i.rto, i.snd_mss, i.non_acquittes, i.sackes, i.cwnd, i.reordonnancement, i.min_rtt, i.pacing), (10, 0, 0, 1, 7, 10, 3, 0, u64::MAX));
}

#[test]
fn info() {
    let (c, _) = paire();
    let i = c.info(maintenant());
    assert_eq!((i.etat, i.phase, i.cwnd, i.snd_mss, i.advmss), (1, 0, 10, MSS as u32, MSS as u32));
    assert_eq!(i.rto / 1000, 200);
}

/// FIONREAD (`tcp_inq`) avec un octet urgent hors du flux : les octets
/// jusqu'à lui ; une fois lus, 0 (la lecture s'arrête à la marque).
#[test]
fn fionread_et_octet_urgent() {
    let (mut c, mut f) = paire();
    ecrire(&mut c, b"ab");
    ecrire(&mut c, b"c");
    c.marquer_urgent();
    let r = t::Reglages { nodelay: true, ..c.reglages };
    c.regler(r, maintenant());
    calmer(&mut c, &mut f);
    assert_eq!((f.lisibles(), f.lisibles_fionread()), (3, 2));
    assert_eq!(lire(&mut f, 100), b"ab");
    assert_eq!(f.lisibles_fionread(), 0);
}

/// Minshall (`tcp_minshall_check`) : un petit segment part quand seuls de
/// GROS segments sont en vol (Nagle, lui, le retiendrait).
#[test]
fn minshall_petit_apres_des_pleins() {
    let (mut c, _f) = paire();
    ecrire(&mut c, &vec![1u8; 2 * MSS as usize + 1]);
    let s = sortants(&mut c);
    assert_eq!(s.iter().map(|(_, o)| o.len()).collect::<Vec<_>>(), vec![MSS as usize, MSS as usize, 1]);
}

/// La mémoire de TCP de toute la machine (`tcp_mem`) : sous pression,
/// SO_SNDBUF ne grandit plus ; à la limite, un envoi n'écrit que dans un
/// tampon vide, une réception ne garde un segment que si sa file est vide,
/// et la file hors d'ordre ne prend plus rien.
#[test]
fn memoire_de_toute_la_machine() {
    // SO_SNDBUF agrandi à l'établissement, sous pression aussi
    // (`tcp_init_buffer_space` ne la regarde pas) ; ensuite, plus : pour un
    // programme qui attend de la place, le même envoi le ferait grandir sans elle
    // (`sndbuf_suit_la_cwnd_si_le_programme_attend`).
    let (mut c, mut f) = paire();
    c.memoire = t::Memoire::Pression;
    let depart = c.sndbuf;
    assert!(depart > 16_384);
    c.choisir_controle(t::Controle::Reno, maintenant());
    grandir(&mut c, &mut f, 30);
    c.marquer_sans_place();
    ecrire(&mut c, b"a");
    calmer(&mut c, &mut f);
    assert_eq!(c.sndbuf, depart);
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.memoire = t::Memoire::Pression;
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    calmer(&mut c, &mut f);
    assert_eq!(c.sndbuf, depart);
    // Limite : un envoi dans un tampon vide passe, puis plus rien.
    c.memoire = t::Memoire::Limite;
    assert_eq!(ecrire(&mut c, b"abc"), 3);
    assert_eq!((c.place(), ecrire(&mut c, b"def")), (0, 0));
    // Limite : un segment dans l'ordre gardé (la file vide), le suivant
    // jeté ; hors d'ordre, rien.
    f.memoire = t::Memoire::Limite;
    let bord = bord(&f);
    let modele = Tcp { drapeaux: tcp::ACK, ack: f.numeros().0, fenetre: 65_535, ..Tcp::default() };
    f.recevoir(&Tcp { seq: bord.wrapping_add(10), ..modele }, Octets(vec![9; 5], 0), maintenant());
    assert_eq!(f.memoire_reception(), 0);
    f.recevoir(&Tcp { seq: bord, ..modele }, Octets(vec![1; 5], 0), maintenant());
    f.recevoir(&Tcp { seq: bord.wrapping_add(5), ..modele }, Octets(vec![2; 5], 0), maintenant());
    assert_eq!(f.lisibles(), 5);
    // Revenue libre : la suite est reprise (l'autre l'aurait retransmise).
    f.memoire = t::Memoire::Libre;
    f.recevoir(&Tcp { seq: bord.wrapping_add(5), ..modele }, Octets(vec![2; 5], 0), maintenant());
    assert_eq!(f.lisibles(), 10);
}

/// `tcp_sequence` : un segment à cheval sur le bord droit n'entre que si la
/// file de réception est vide ; le bord gauche est `rcv_wup`, pas RCV.NXT.
#[test]
fn segments_acceptables_comme_linux() {
    let (mut c, _f) = paire();
    let modele = Tcp { drapeaux: tcp::ACK, ack: c.numeros().0, fenetre: 1000, ..Tcp::default() };
    let n = bord(&c);
    let w = c.fenetre_annoncee() as usize;
    // À cheval, file vide : gardé en entier, au-delà du bord.
    c.recevoir(&Tcp { seq: n, ..modele }, Octets(vec![1; w + 100], 0), maintenant());
    assert_eq!(c.lisibles(), w + 100);
    let _ = sortants(&mut c);
    // Le même, la file n'étant plus vide : refusé, avec un ACK.
    let n = bord(&c);
    let garde = c.lisibles();
    let w = c.fenetre_annoncee() as usize;
    c.recevoir(&Tcp { seq: n, ..modele }, Octets(vec![2; w + 100], 0), maintenant());
    assert_eq!(c.lisibles(), garde);
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].0.ack == n);

    let (mut c, _f) = paire();
    ecrire(&mut c, b"abc");
    let _ = sortants(&mut c);
    let (una, n) = (c.numeros().0, bord(&c));
    let modele = Tcp { drapeaux: tcp::ACK, ack: una, fenetre: 1000, ..Tcp::default() };
    // Des données arrivent, notre ACK n'est pas encore parti : un ACK de
    // l'autre, du numéro d'avant (`rcv_wup`), passe encore...
    c.recevoir(&Tcp { seq: n, ..modele }, Octets(vec![3; 100], 0), maintenant());
    c.recevoir(&Tcp { seq: n, ack: una.wrapping_add(2), ..modele }, vide(), maintenant());
    assert_eq!(c.numeros().0, una.wrapping_add(2));
    // ... notre ACK parti, ce numéro est vieux : il reçoit l'ACK à jour, et
    // ne compte pas.
    let _ = sortants(&mut c);
    c.recevoir(&Tcp { seq: n, ack: una.wrapping_add(3), ..modele }, vide(), maintenant());
    assert_eq!(c.numeros().0, una.wrapping_add(2));
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].0.ack == n.wrapping_add(100));
}

/// Une fenêtre fermée ne laisse passer qu'un FIN seul.
#[test]
fn fenetre_fermee_seul_un_fin_passe() {
    let (mut c, _f) = paire();
    let modele = Tcp { drapeaux: tcp::ACK, ack: c.numeros().0, fenetre: 1000, ..Tcp::default() };
    // Remplir jusqu'à fermer la fenêtre, sans lire.
    let mut n = bord(&c);
    for _ in 0..1000 {
        if c.fenetre_annoncee() == 0 {
            break;
        }
        let m = (c.fenetre_annoncee() as usize).min(1000);
        c.recevoir(&Tcp { seq: n, ..modele }, Octets(vec![1; m], 0), maintenant());
        n = bord(&c);
        let _ = sortants(&mut c);
    }
    assert_eq!(c.fenetre_annoncee(), 0);
    let lus = c.lisibles();
    // Une donnée au bord : jetée, avec un ACK.
    c.recevoir(&Tcp { seq: n, ..modele }, Octets(vec![2; 1], 0), maintenant());
    assert_eq!(c.lisibles(), lus);
    assert_eq!(sortants(&mut c).len(), 1);
    // Un FIN avec une donnée : refusé de même (il attend la fenêtre).
    c.recevoir(&Tcp { seq: n, drapeaux: tcp::ACK | tcp::FIN, ..modele }, Octets(vec![2; 1], 0), maintenant());
    assert!(!c.fin_recue());
    let _ = sortants(&mut c);
    // Un FIN seul, la file pleine : `tcp_sequence` le refuse aussi (il est
    // au-delà du bord, et la file n'est pas vide).
    c.recevoir(&Tcp { seq: n, drapeaux: tcp::ACK | tcp::FIN, ..modele }, vide(), maintenant());
    assert!(!c.fin_recue());
    let _ = sortants(&mut c);
    // Tout lu, la fenêtre pas encore rouverte : un FIN seul passe ; une
    // donnée, non.
    let _ = c.lire::<()>(usize::MAX, false, |m| Ok(m.len()));
    assert_eq!(c.fenetre_annoncee(), 0);
    c.recevoir(&Tcp { seq: n, ..modele }, Octets(vec![2; 1], 0), maintenant());
    assert_eq!(c.lisibles(), 0);
    c.recevoir(&Tcp { seq: n, drapeaux: tcp::ACK | tcp::FIN, ..modele }, vide(), maintenant());
    assert!(c.fin_recue());
    assert_eq!(c.etat(), Etat::AttenteFermeture);
}

/// `tcp_reset` et `tcp_reset_check` : RCV.NXT - 1 vaut après un FIN ; EPIPE
/// en CLOSE_WAIT, ECONNRESET ailleurs, LAST_ACK et CLOSING compris.
#[test]
fn rst_apres_le_fin() {
    for (fermer, attendu) in [(false, t::EPIPE), (true, t::ECONNRESET)] {
        let (mut c, mut f) = paire();
        f.fermer_envoi();
        calmer(&mut c, &mut f);
        assert_eq!(c.etat(), Etat::AttenteFermeture);
        if fermer {
            c.fermer_envoi();
            let _ = sortants(&mut c);
            assert_eq!(c.etat(), Etat::DernierAck);
        }
        let n = bord(&c);
        // Deux de moins : hors de la fenêtre, rien (un RST n'a pas d'ACK).
        c.recevoir(&Tcp { drapeaux: tcp::RST, seq: n.wrapping_sub(2), ..Tcp::default() }, vide(), maintenant());
        assert!(c.etat() != Etat::Fermee);
        // Un de moins, le numéro du FIN : accepté.
        c.recevoir(&Tcp { drapeaux: tcp::RST, seq: n.wrapping_sub(1), ..Tcp::default() }, vide(), maintenant());
        assert_eq!((c.etat(), c.prendre_erreur()), (Etat::Fermee, attendu));
    }
    // En ESTABLISHED, le même numéro n'est qu'hors de la fenêtre.
    let (mut c, _f) = paire();
    let n = bord(&c);
    c.recevoir(&Tcp { drapeaux: tcp::RST, seq: n.wrapping_sub(1), ..Tcp::default() }, vide(), maintenant());
    assert_eq!(c.etat(), Etat::Etablie);
}

/// Un FIN retransmis en CLOSE_WAIT reçoit son ACK (le chemin de
/// `tcp_data_queue` pour ce qui précède RCV.NXT) ; de nouvelles données après
/// le FIN sont ignorées.
#[test]
fn apres_le_fin_doublons_acquittes() {
    let (mut c, mut f) = paire();
    f.fermer_envoi();
    let s = sortants(&mut f);
    let fin = s.iter().find(|x| x.0.drapeaux & tcp::FIN != 0).unwrap().0;
    c.recevoir(&fin, vide(), maintenant());
    let _ = sortants(&mut c);
    assert_eq!(c.etat(), Etat::AttenteFermeture);
    c.recevoir(&fin, vide(), maintenant());
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].0.drapeaux == tcp::ACK && s[0].0.ack == fin.seq.wrapping_add(1));
    c.recevoir(&Tcp { seq: fin.seq.wrapping_add(1), ack: fin.ack, drapeaux: tcp::ACK, fenetre: 1000, ..Tcp::default() },
               Octets(vec![1; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 0);
}

/// `tcp_check_req`, chaque cas à sa place : le SYN répété, l'ACK qui
/// n'acquitte pas notre SYN, hors de la fenêtre, un autre SYN, un RST.
#[test]
fn fille_comme_tcp_check_req() {
    let cree = || {
        let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
        let (syn, _) = sortants(&mut c)[0];
        let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
        let _ = sortants(&mut f);
        (syn, f)
    };
    // Le SYN répété : un SYN-ACK, la fille reste ; limité à un par 500 ms.
    let (syn, mut f) = cree();
    f.recevoir(&syn, vide(), maintenant());
    let s = sortants(&mut f);
    assert!(s.len() == 1 && s[0].0.drapeaux == tcp::SYN | tcp::ACK);
    f.recevoir(&syn, vide(), maintenant());
    assert!(sortants(&mut f).is_empty());
    avancer(500 * MS);
    f.recevoir(&syn, vide(), maintenant());
    assert_eq!(sortants(&mut f).len(), 1);
    // Un ACK faux : RST de son numéro ; la fille reste.
    let (syn, mut f) = cree();
    let modele = Tcp { source: syn.source, destination: syn.destination, seq: syn.seq.wrapping_add(1), ack: 7001, drapeaux: tcp::ACK, fenetre: 1000, ..Tcp::default() };
    f.recevoir(&Tcp { ack: 9999, ..modele }, vide(), maintenant());
    let s = sortants(&mut f);
    assert!(s.len() == 1 && s[0].0.drapeaux == tcp::RST && s[0].0.seq == 9999);
    assert_eq!(f.etat(), Etat::SynRecu);
    // Le même avec RST : pas de réponse, la fille reste.
    f.recevoir(&Tcp { ack: 9999, drapeaux: tcp::ACK | tcp::RST, ..modele }, vide(), maintenant());
    assert!(sortants(&mut f).is_empty());
    assert_eq!(f.etat(), Etat::SynRecu);
    // Hors de la fenêtre : un ACK, et rien d'autre.
    f.recevoir(&Tcp { seq: syn.seq.wrapping_add(1 << 30), ..modele }, vide(), maintenant());
    let s = sortants(&mut f);
    assert!(s.len() == 1 && s[0].0.drapeaux == tcp::ACK);
    assert_eq!(f.etat(), Etat::SynRecu);
    // Un RST dans la fenêtre : elle disparaît, sans réponse.
    f.recevoir(&Tcp { drapeaux: tcp::RST, ack: 0, ..modele }, vide(), maintenant());
    assert!(sortants(&mut f).is_empty());
    assert_eq!(f.etat(), Etat::Fermee);
    // Un autre SYN dans la fenêtre : RST, et elle disparaît.
    let (syn, mut f) = cree();
    f.recevoir(&Tcp { seq: syn.seq.wrapping_add(10), drapeaux: tcp::SYN, ..syn }, vide(), maintenant());
    let s = sortants(&mut f);
    assert!(s.len() == 1 && s[0].0.drapeaux == tcp::RST | tcp::ACK && s[0].0.ack == syn.seq.wrapping_add(11));
    assert_eq!(f.etat(), Etat::Fermee);
    // Un segment sans ACK : jeté.
    let (syn, mut f) = cree();
    f.recevoir(&Tcp { seq: syn.seq.wrapping_add(1), drapeaux: tcp::PSH, ..syn }, Octets(vec![1; 10], 0), maintenant());
    assert!(sortants(&mut f).is_empty());
    assert_eq!((f.etat(), f.lisibles()), (Etat::SynRecu, 0));
    // Le bon ACK, avec des données : établie, et les données gardées.
    f.recevoir(&Tcp { seq: syn.seq.wrapping_add(1), ack: 7001, drapeaux: tcp::ACK, fenetre: 1000, ..syn }, Octets(vec![1; 10], 0), maintenant());
    assert_eq!((f.etat(), f.lisibles()), (Etat::Etablie, 10));
}

/// Une entrée de TIME_WAIT (`tcp_timewait_state_process`).
#[test]
fn time_wait_comme_linux() {
    let (mut c, mut f) = paire();
    c.fermer_envoi();
    calmer(&mut c, &mut f);
    f.fermer_envoi();
    calmer(&mut c, &mut f);
    assert_eq!(c.etat(), Etat::TempsAttente);
    let mut a = c.en_attente(false);
    let n = bord(&c);
    let modele = Tcp { source: 80, destination: 40000, seq: n, ack: a.snd_nxt, drapeaux: tcp::ACK, fenetre: 1000, ..Tcp::default() };
    // Un ACK nu au bord gauche : prolongée, sans réponse.
    let r = a.recevoir(&modele, 0, maintenant());
    assert!(r.prolonger && !r.ack && !r.effacer);
    // Un FIN retransmis : réacquitté, prolongée. Il compte comme des données
    // sans SYN : sa réponse n'est jamais limitée.
    let fin = Tcp { seq: n.wrapping_sub(1), drapeaux: tcp::ACK | tcp::FIN, ..modele };
    let r = a.recevoir(&fin, 0, maintenant());
    assert!(r.ack && r.prolonger);
    assert!(a.recevoir(&fin, 0, maintenant()).ack);
    let h = a.entete_ack(maintenant());
    assert_eq!((h.seq, h.ack, h.drapeaux), (a.snd_nxt, n, tcp::ACK));
    // Sa fenêtre : celle de la connexion, à son échelle (pas 0).
    assert_eq!(h.fenetre as u32, a.rcv_wnd >> a.echelle);
    assert!(h.fenetre > 0);
    // Un ACK nu hors du bord : réponse limitée à une par 500 ms.
    let vieux = Tcp { seq: n.wrapping_add(1000), ..modele };
    assert!(a.recevoir(&vieux, 0, maintenant()).ack);
    assert!(!a.recevoir(&vieux, 0, maintenant()).ack);
    avancer(500 * MS);
    assert!(a.recevoir(&vieux, 0, maintenant()).ack);
    // Un SYN plus loin : le quadruplet repris, le numéro initial bien au-delà.
    let syn = Tcp { seq: n.wrapping_add(5), drapeaux: tcp::SYN, ack: 0, ..modele };
    assert_eq!(a.recevoir(&syn, 0, maintenant()).reprendre, Some(a.snd_nxt.wrapping_add(65_537)));
    // Un SYN plus vieux : l'ACK, sans prolonger (il peut être neuf et tiré au
    // hasard en deçà).
    avancer(500 * MS);
    let r = a.recevoir(&Tcp { seq: n.wrapping_sub(5), ..syn }, 0, maintenant());
    assert!(r.reprendre.is_none() && r.ack && !r.prolonger);
    // Un RST au bord gauche l'efface ; ailleurs, rien.
    assert_eq!(a.recevoir(&Tcp { seq: n.wrapping_add(9), drapeaux: tcp::RST, ..modele }, 0, maintenant()), Default::default());
    assert!(a.recevoir(&Tcp { drapeaux: tcp::RST, ..modele }, 0, maintenant()).effacer);
}

/// Une orpheline en FIN_WAIT_2 : son sous-état.
#[test]
fn fin_wait_2_d_une_orpheline() {
    let (mut c, mut f) = paire();
    c.fermer_envoi();
    calmer(&mut c, &mut f);
    assert_eq!(c.etat(), Etat::FinAttente2);
    let mut a = c.en_attente(true);
    let n = bord(&c);
    let modele = Tcp { source: 80, destination: 40000, seq: n, ack: a.snd_nxt, drapeaux: tcp::ACK, fenetre: 1000, ..Tcp::default() };
    // Un ACK seul : rien.
    assert_eq!(a.recevoir(&modele, 0, maintenant()), Default::default());
    // Hors de la fenêtre : un ACK.
    assert!(a.recevoir(&Tcp { seq: n.wrapping_add(1 << 30), ..modele }, 0, maintenant()).ack);
    // Des données : RST, et l'entrée disparaît.
    let r = a.recevoir(&modele, 10, maintenant());
    assert!(r.rst && r.effacer);
    // Un SYN : de même.
    let r = a.recevoir(&Tcp { drapeaux: tcp::SYN, ..modele }, 0, maintenant());
    assert!(r.rst && r.effacer);
    // Un RST : effacée.
    assert!(a.recevoir(&Tcp { drapeaux: tcp::RST, ..modele }, 0, maintenant()).effacer);
    // Le FIN de l'autre : un vrai TIME_WAIT, son numéro acquitté.
    let r = a.recevoir(&Tcp { drapeaux: tcp::ACK | tcp::FIN, ..modele }, 0, maintenant());
    assert!(r.ack && r.prolonger && !a.fin_attente2);
    assert_eq!(a.rcv_nxt, n.wrapping_add(1));
}

/// Le modèle de Linux : SND.NXT ne recule jamais ; après un RTO, tout est
/// marqué perdu, la tête part, et le reste un par un à mesure que les ACK
/// ouvrent la cwnd (`tcp_enter_loss`, `tcp_xmit_retransmit_queue`).
#[test]
fn le_rto_ne_recule_pas_snd_nxt() {
    let (mut c, _f) = paire();
    ecrire(&mut c, &vec![5u8; 4 * MSS as usize]);
    assert_eq!(sortants(&mut c).len(), 4);
    let (una, nxt, _) = c.numeros();
    echeance_suivante(&mut c);
    assert_eq!(c.numeros().1, nxt, "SND.NXT reste");
    let i = c.info(maintenant());
    assert_eq!((i.phase, i.perdus, i.non_acquittes), (4, 4, 4));
    assert_eq!(i.cwnd, 1);
    // La tête seule, marquée renvoyée.
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].0.seq == una && s[0].1.len() == MSS as usize);
    let i = c.info(maintenant());
    assert_eq!((i.retransmis, i.total_retrans), (1, 1));
    // Son ACK : deux segments de plus (la cwnd de 1 à 2, le démarrage lent).
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una.wrapping_add(MSS as u32), fenetre: 65_535, ..Tcp::default() };
    c.recevoir(&m, vide(), maintenant());
    let s = sortants(&mut c);
    assert_eq!(s.iter().map(|x| x.0.seq).collect::<Vec<_>>(), [una.wrapping_add(MSS as u32), una.wrapping_add(2 * MSS as u32)]);
    assert_eq!(c.numeros().1, nxt);
    // Tout acquitté : la file est vide, le minuteur arrêté. Sans SACK, l'état
    // reste jusqu'à ce qu'un ACK passe `high_seq`
    // (`tcp_is_non_sack_preventing_reopen`, RFC 2582).
    c.recevoir(&Tcp { ack: nxt, ..m }, vide(), maintenant());
    let i = c.info(maintenant());
    assert_eq!((i.phase, i.non_acquittes, i.retransmis, i.perdus), (4, 0, 0, 0));
    assert_eq!(c.echeance(), None);
    ecrire(&mut c, b"x");
    assert_eq!(sortants(&mut c).len(), 1);
    c.recevoir(&Tcp { ack: nxt.wrapping_add(1), ..m }, vide(), maintenant());
    assert_eq!(c.info(maintenant()).phase, 0);
}

/// Un segment acquitté en partie reste en file ; s'il faut le renvoyer, sa
/// tête est retirée (`tcp_trim_head`). Karn : un ACK qui couvre un segment
/// renvoyé ne mesure rien ; un ACK d'un segment jamais renvoyé, si.
#[test]
fn file_acquittement_partiel_et_karn() {
    let (mut c, _f) = paire();
    ecrire(&mut c, &vec![5u8; 2 * MSS as usize]);
    sortants(&mut c);
    let (una, _, _) = c.numeros();
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una.wrapping_add(100), fenetre: 65_535, ..Tcp::default() };
    c.recevoir(&m, vide(), maintenant());
    assert_eq!(c.info(maintenant()).non_acquittes, 2);
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].0.seq == una.wrapping_add(100) && s[0].1.len() == MSS as usize - 100);
    // Le renvoi acquitté : pas de mesure, le RTO reculé reste.
    let rto = c.congestion().2;
    avancer(50 * MS);
    c.recevoir(&Tcp { ack: una.wrapping_add(MSS as u32), ..m }, vide(), maintenant());
    assert_eq!(c.congestion().2, rto);
    // Un autre acquitté, jamais renvoyé : hors perte... il était marqué perdu,
    // mais pas renvoyé : une mesure, et le RTO revient à l'estimateur.
    avancer(50 * MS);
    c.recevoir(&Tcp { ack: una.wrapping_add(2 * MSS as u32), ..m }, vide(), maintenant());
    assert!(c.congestion().2 < rto);
}

/// Un segment renvoyé trop grand pour ce que laisse la fenêtre est coupé
/// (`tcp_fragment`) : la suite garde ses marques, et ce qui est en file reste
/// exact.
#[test]
fn renvoi_coupe_par_la_fenetre() {
    let (mut c, _f) = paire();
    ecrire(&mut c, &vec![5u8; MSS as usize]);
    sortants(&mut c);
    let (una, nxt, _) = c.numeros();
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 2, ..Tcp::default() };
    // L'échelle de l'autre multiplie par 128 : 256 octets.
    c.recevoir(&Tcp { seq: bord(&c).wrapping_add(0), ..m }, vide(), maintenant());
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].1.len() == 256, "{:?}", s.iter().map(|x| x.1.len()).collect::<Vec<_>>());
    let i = c.info(maintenant());
    assert_eq!((i.non_acquittes, i.perdus, i.retransmis), (2, 2, 1));
    assert_eq!(c.numeros().1, nxt);
    // La suite part quand l'ACK ouvre la fenêtre et la cwnd.
    c.recevoir(&Tcp { ack: una.wrapping_add(256), fenetre: 100, ..m }, vide(), maintenant());
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].0.seq == una.wrapping_add(256) && s[0].1.len() == MSS as usize - 256);
    // Un FIN porté par un segment coupé reste sur la dernière moitié : ici,
    // le dernier ACK vide la file.
    c.recevoir(&Tcp { ack: nxt, fenetre: 100, ..m }, vide(), maintenant());
    assert_eq!(c.info(maintenant()).non_acquittes, 0);
}

/// RFC 5961 5.2 et `tcp_ack` : un ACK de ce qui n'a jamais été envoyé jette le
/// segment, sans réponse ; un ACK plus vieux que la plus grande fenêtre reçoit
/// un ACK de défi et le segment est jeté aussi ; un vieil ACK ordinaire
/// n'empêche pas ses données d'entrer.
#[test]
fn ack_impossible_et_ack_trop_vieux() {
    let (mut c, mut f) = paire();
    ecrire(&mut c, &vec![5u8; 3000]);
    calmer(&mut c, &mut f);
    let (una, nxt, _) = c.numeros();
    assert_eq!(una, nxt);
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: nxt, fenetre: 65_535, ..Tcp::default() };
    // Trop loin : rien n'entre, rien ne part.
    c.recevoir(&Tcp { ack: nxt.wrapping_add(1), ..m }, Octets(vec![1; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 0);
    assert!(sortants(&mut c).is_empty());
    // Un peu vieux : ses données entrent.
    c.recevoir(&Tcp { ack: nxt.wrapping_sub(1000), ..m }, Octets(vec![1; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 10);
    sortants(&mut c);
    // Plus vieux que ce qu'on a jamais acquitté : un ACK de défi, et rien
    // n'entre.
    avancer(500 * MS);
    c.recevoir(&Tcp { seq: bord(&c), ack: nxt.wrapping_sub(100_000), ..m }, Octets(vec![1; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 10);
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].1.is_empty());
}

/// Une paire qui a négocié les horodatages.
fn paire_ts() -> (Connexion, Connexion) {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.proposer_horodatages(1_000_000);
    let (syn, _) = sortants(&mut c)[0];
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    f.decalage_horodatages(5_000_000);
    let s = sortants(&mut f);
    c.recevoir(&s[0].0, vide(), maintenant());
    livrer(&mut c, &mut f);
    assert_eq!((c.etat(), f.etat()), (Etat::Etablie, Etat::Etablie));
    (c, f)
}

/// La négociation (RFC 7323 3.2) : TSval, notre horloge en ms plus le décalage ;
/// TSecr, le dernier reçu ; dans chaque segment une fois en service ; sinon
/// jamais. Ils prennent 12 octets à chaque segment (`tcp_sync_mss`) et à ce
/// qu'on dit pouvoir recevoir (`advmss`).
#[test]
fn horodatages_negocies() {
    avancer(3 * MS);
    let ms = (maintenant() / MS) as u32;
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.proposer_horodatages(1_000_000);
    let (syn, _) = sortants(&mut c)[0];
    assert_eq!(syn.options.horodatage, Some((1_000_000 + ms, 0)));
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    f.decalage_horodatages(5_000_000);
    let (sa, _) = sortants(&mut f)[0];
    assert_eq!(sa.options.horodatage, Some((5_000_000 + ms, 1_000_000 + ms)));
    avancer(2 * MS);
    c.recevoir(&sa, vide(), maintenant());
    let s = sortants(&mut c);
    assert_eq!(s[0].0.options.horodatage, Some((1_000_002 + ms, 5_000_000 + ms)));
    f.recevoir(&s[0].0, vide(), maintenant());
    assert_eq!((c.etat(), f.etat()), (Etat::Etablie, Etat::Etablie));
    // Les deux côtés : TCPI_OPT_TIMESTAMPS, 12 octets de moins.
    for x in [&c, &f] {
        let i = x.info(maintenant());
        assert_eq!((i.options & 1, i.snd_mss, i.advmss, i.pmtu), (1, MSS as u32 - 12, MSS as u32 - 12, MSS as u32 + 40));
    }
    // Un segment plein fait donc 1448 octets, et porte l'option.
    ecrire(&mut c, &vec![1u8; MSS as usize]);
    let s = sortants(&mut c);
    assert_eq!(s[0].1.len(), MSS as usize - 12);
    assert!(s.iter().all(|x| x.0.options.horodatage.is_some()));
    // Le SYN sans l'option : jamais en service, ni l'un ni l'autre.
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    let (syn, _) = sortants(&mut c)[0];
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    let (sa, _) = sortants(&mut f)[0];
    assert_eq!(sa.options.horodatage, None);
    c.recevoir(&sa, vide(), maintenant());
    assert_eq!(c.info(maintenant()).options & 1, 0);
    // Proposés, mais pas de l'autre côté : retirés, MSS entier.
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.proposer_horodatages(1);
    let (syn, _) = sortants(&mut c)[0];
    let sans = Tcp { options: tcp::Options { horodatage: None, ..syn.options }, ..syn };
    let mut f = Connexion::depuis_syn(&sans, 7000, MSS, 131_072, 16_384, ECHELLE);
    let (sa, _) = sortants(&mut f)[0];
    c.recevoir(&sa, vide(), maintenant());
    let s = sortants(&mut c);
    assert_eq!(s[0].0.options.horodatage, None);
    assert_eq!(c.info(maintenant()).snd_mss, MSS as u32);
}

/// PAWS (`tcp_validate_incoming`, les six règles).
#[test]
fn paws_comme_linux() {
    let (mut c, mut f) = paire_ts();
    calmer(&mut c, &mut f);
    avancer(100 * MS);
    let n = bord(&c);
    let una = c.numeros().0;
    let r = |ts: u32| Tcp { drapeaux: tcp::ACK, seq: n, ack: una, fenetre: 1000, options: tcp::Options { horodatage: Some((ts, 0)), ..Default::default() }, ..Tcp::default() };
    // Un TSval d'un cran plus vieux que le dernier passe encore (fenêtre 1).
    let (val, _) = { ecrire(&mut f, b"x"); sortants(&mut f)[0].0.options.horodatage.unwrap() };
    let d = Tcp { seq: n, ..r(val) };
    let mut f2 = d;
    f2.ack = una;
    c.recevoir(&f2, Octets(vec![1; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 10);
    let _ = sortants(&mut c);
    let n = bord(&c);
    c.recevoir(&Tcp { seq: n, ..r(val.wrapping_sub(1)) }, Octets(vec![2; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 20);
    let _ = sortants(&mut c);
    // Deux crans : des données refusées, avec un ACK.
    let n = bord(&c);
    avancer(600 * MS);
    c.recevoir(&Tcp { seq: n, ..r(val.wrapping_sub(2)) }, Octets(vec![3; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 20);
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].1.is_empty());
    // Un ACK pur au bord gauche, dupliqué, sans changement de fenêtre, un peu
    // vieux : accepté (`tcp_disordered_ack_check`), rien en réponse. (Le premier,
    // à jour, pose `snd_wl1` ; un numéro plus loin changerait la fenêtre.)
    avancer(600 * MS);
    c.recevoir(&Tcp { seq: n, ..r(val) }, vide(), maintenant());
    let _ = sortants(&mut c);
    avancer(600 * MS);
    c.recevoir(&Tcp { seq: n, ..r(val.wrapping_sub(2)) }, vide(), maintenant());
    assert!(sortants(&mut c).is_empty());
    // Avec un changement de fenêtre, le même reçoit un ACK.
    c.recevoir(&Tcp { seq: n, fenetre: 2000, ..r(val.wrapping_sub(2)) }, vide(), maintenant());
    assert_eq!(sortants(&mut c).len(), 1);
    // Un ACK pur plus vieux que le bord gauche : jeté, sans réponse (nouveau en
    // 6.x : PAWS_OLD_ACK), même après la limite des 500 ms.
    avancer(600 * MS);
    c.recevoir(&Tcp { seq: n.wrapping_sub(5), ..r(val.wrapping_sub(2)) }, vide(), maintenant());
    assert!(sortants(&mut c).is_empty());
    // Un SYN : l'ACK de défi.
    avancer(600 * MS);
    c.recevoir(&Tcp { seq: n, drapeaux: tcp::SYN, ..r(val.wrapping_sub(2)) }, vide(), maintenant());
    assert_eq!(sortants(&mut c).len(), 1);
    assert_eq!(c.etat(), Etat::Etablie);
    // Un RST passe toujours PAWS, dans une connexion : sa propre règle le juge.
    c.recevoir(&Tcp { seq: n, drapeaux: tcp::RST, ..r(val.wrapping_sub(1000)) }, vide(), maintenant());
    assert_eq!(c.etat(), Etat::Fermee);
    // Passé 2147 s (`TCP_PAWS_WRAP`), `ts_recent` ne vaut plus.
    let (mut c, mut f) = paire_ts();
    calmer(&mut c, &mut f);
    let n = bord(&c);
    let una = c.numeros().0;
    let (val, _) = { ecrire(&mut f, b"x"); sortants(&mut f)[0].0.options.horodatage.unwrap() };
    let m = Tcp { drapeaux: tcp::ACK, seq: n, ack: una, fenetre: 1000, options: tcp::Options { horodatage: Some((val, 0)), ..Default::default() }, ..Tcp::default() };
    c.recevoir(&m, Octets(vec![1; 10], 0), maintenant());
    let _ = sortants(&mut c);
    let vieux = Tcp { seq: bord(&c), options: tcp::Options { horodatage: Some((val.wrapping_sub(5000), 0)), ..Default::default() }, ..m };
    avancer(2146 * 1000 * MS);
    c.recevoir(&vieux, Octets(vec![2; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 10);
    let _ = sortants(&mut c);
    avancer(1000 * MS);
    c.recevoir(&vieux, Octets(vec![2; 10], 0), maintenant());
    assert_eq!(c.lisibles(), 20);
}

/// `ts_recent` : seulement d'un segment qui couvre `rcv_wup` (RFC 7323 4.3 : un
/// segment plus loin ne dit rien de l'ordre du réseau) et qui passe PAWS.
#[test]
fn ts_recent_d_un_segment_au_bord() {
    let (mut c, mut f) = paire_ts();
    calmer(&mut c, &mut f);
    let n = bord(&c);
    let una = c.numeros().0;
    let m = |ts: u32, seq: u32| Tcp { drapeaux: tcp::ACK, seq, ack: una, fenetre: 1000, options: tcp::Options { horodatage: Some((ts, 0)), ..Default::default() }, ..Tcp::default() };
    let (val, _) = { ecrire(&mut f, b"x"); sortants(&mut f)[0].0.options.horodatage.unwrap() };
    // Hors d'ordre : gardé, mais `ts_recent` ne bouge pas.
    c.recevoir(&m(val + 50, n.wrapping_add(100)), Octets(vec![1; 10], 0), maintenant());
    let s = sortants(&mut c);
    assert_ne!(s[0].0.options.horodatage.unwrap().1, val + 50);
    // Au bord : il devient celui que nos segments renvoient.
    c.recevoir(&m(val + 60, n), Octets(vec![1; 10], 0), maintenant());
    let s = sortants(&mut c);
    assert_eq!(s[0].0.options.horodatage.unwrap().1, val + 60);
}

/// `tcp_ack_update_rtt` : TSecr seulement si l'heure d'envoi ne dit rien (Karn :
/// tout l'acquitté a été renvoyé) ; pas sans cela : l'horloge de TSecr compte en
/// ms, une boucle de quelques µs verrait son SRTT monter à 1 ms.
#[test]
fn rtt_par_tsecr_seulement_apres_un_renvoi() {
    // Sans renvoi : le SRTT suit l'heure d'envoi, TSecr n'y fait rien.
    let (mut c, mut f) = paire_ts();
    calmer(&mut c, &mut f);
    ecrire(&mut c, &vec![1u8; 3 * 1448]);
    avancer(10 * MS);
    let s = sortants(&mut c);
    avancer(10 * MS);
    let una = c.numeros().0;
    let (val, ecr) = s[0].0.options.horodatage.unwrap();
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una.wrapping_add(1448), fenetre: 1000, options: tcp::Options { horodatage: Some((val, val.wrapping_sub(1000))), ..Default::default() }, ..Tcp::default() };
    let _ = ecr;
    c.recevoir(&m, vide(), maintenant());
    let i = c.info(maintenant());
    assert!(i.rtt / 1000 <= 11, "SRTT {} us", i.rtt);
    // Un renvoi : Karn interdit l'heure d'envoi ; TSecr donne 30 ms, l'écart à
    // l'horodatage du renvoi qu'il cite.
    let (mut c, mut f) = paire_ts();
    calmer(&mut c, &mut f);
    ecrire(&mut c, b"abc");
    let _ = sortants(&mut c);
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    let (val, ecr) = s[0].0.options.horodatage.unwrap();
    avancer(30 * MS);
    let una = c.numeros().0;
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una.wrapping_add(3), fenetre: 1000, options: tcp::Options { horodatage: Some((ecr, val)), ..Default::default() }, ..Tcp::default() };
    // Le SRTT partait de presque rien (la poignée de main à l'heure 0) : un
    // huitième de 30 ms.
    assert_eq!(c.info(maintenant()).rtt, 0);
    c.recevoir(&m, vide(), maintenant());
    assert_eq!(c.info(maintenant()).rtt, 3750);
}

/// Un SYN-ACK dont TSecr n'est pas entre notre premier SYN et maintenant : RST
/// (`PAWSACTIVEREJECTED`), SYN_SENT reste. Une fille : un TSecr qui n'est
/// aucun de ceux de ses SYN-ACK (`tsecr_reject`, 6.18), et un TSval trop vieux :
/// un ACK, et elle reste.
#[test]
fn tsecr_de_la_poignee_de_main() {
    avancer(10 * MS);
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.proposer_horodatages(1_000_000);
    let (syn, _) = sortants(&mut c)[0];
    let val_syn = syn.options.horodatage.unwrap().0;
    avancer(5 * MS);
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    f.decalage_horodatages(5_000_000);
    let (sa, _) = sortants(&mut f)[0];
    let faux = Tcp { options: tcp::Options { horodatage: Some((9, val_syn.wrapping_sub(1))), ..sa.options }, ..sa };
    c.recevoir(&faux, vide(), maintenant());
    let s = sortants(&mut c);
    assert!(s.len() == 1 && s[0].0.drapeaux == tcp::RST && s[0].0.options == tcp::Options::default());
    assert_eq!(c.etat(), Etat::SynEnvoye);
    let (val_sa, _) = sa.options.horodatage.unwrap();
    let bon = Tcp { source: syn.source, destination: syn.destination, seq: syn.seq.wrapping_add(1), ack: 7001, drapeaux: tcp::ACK, fenetre: 1000, options: tcp::Options { horodatage: Some((val_syn, val_sa)), ..Default::default() }, ..Tcp::default() };
    // TSecr hors de nos SYN-ACK.
    f.recevoir(&Tcp { options: tcp::Options { horodatage: Some((val_syn, val_sa.wrapping_add(1))), ..Default::default() }, ..bon }, vide(), maintenant());
    assert_eq!(f.etat(), Etat::SynRecu);
    let s = sortants(&mut f);
    assert!(s.len() == 1 && s[0].0.drapeaux == tcp::ACK);
    // TSval plus vieux que celui du SYN : PAWS, fenêtre 0.
    avancer(500 * MS);
    f.recevoir(&Tcp { options: tcp::Options { horodatage: Some((val_syn.wrapping_sub(1), val_sa)), ..Default::default() }, ..bon }, vide(), maintenant());
    assert_eq!(f.etat(), Etat::SynRecu);
    assert_eq!(sortants(&mut f).len(), 1);
    // Le bon : établie.
    f.recevoir(&bon, vide(), maintenant());
    assert_eq!(f.etat(), Etat::Etablie);
}

/// TIME_WAIT et les horodatages (`tcp_timewait_state_process`, `tcp_paws_reject`,
/// `tcp_twsk_unique`).
#[test]
fn time_wait_avec_horodatages() {
    let (mut c, mut f) = paire_ts();
    c.fermer_envoi();
    calmer(&mut c, &mut f);
    f.fermer_envoi();
    calmer(&mut c, &mut f);
    assert_eq!(c.etat(), Etat::TempsAttente);
    let mut a = c.en_attente(false);
    let n = bord(&c);
    let ts = a.ts.unwrap();
    let snd_nxt = a.snd_nxt;
    let m = |val: u32| Tcp { source: 80, destination: 40000, seq: n, ack: snd_nxt, drapeaux: tcp::ACK, fenetre: 1000, options: tcp::Options { horodatage: Some((val, 0)), ..Default::default() }, ..Tcp::default() };
    // Son ACK porte les horodatages : TSval à notre heure, TSecr le dernier reçu.
    avancer(7 * MS);
    let h = a.entete_ack(maintenant());
    assert_eq!(h.options.horodatage, Some((ts.valeur(maintenant()), ts.recent)));
    // Un ACK nu au bord gauche, plus récent : retenu.
    let r = a.recevoir(&m(ts.recent + 10), 0, maintenant());
    assert!(r.prolonger && !r.ack);
    assert_eq!(a.ts.unwrap().recent, ts.recent + 10);
    // Plus vieux : rejeté, un ACK, et elle est prolongée.
    let r = a.recevoir(&m(ts.recent), 0, maintenant());
    assert!(r.ack && r.prolonger);
    // Un SYN en deçà du bord, d'un horodatage plus récent : le quadruplet repris.
    let syn = Tcp { seq: n.wrapping_sub(100), ack: 0, drapeaux: tcp::SYN, ..m(ts.recent + 20) };
    assert!(a.recevoir(&syn, 0, maintenant()).reprendre.is_some());
    // Plus vieux, même plus loin : non.
    avancer(500 * MS);
    let r = a.recevoir(&Tcp { seq: n.wrapping_add(100), ..syn_ts(syn, ts.recent) }, 0, maintenant());
    assert!(r.reprendre.is_none() && r.ack);
    // Un RST trop vieux : rien, tant que l'entrée n'a pas 60 s depuis son dernier
    // horodatage ; ensuite, cru (`TCP_PAWS_MSL`).
    let rst = Tcp { seq: n, drapeaux: tcp::RST, ..m(ts.recent) };
    assert!(!a.recevoir(&rst, 0, maintenant()).effacer);
    avancer(60_000 * MS);
    assert!(a.recevoir(&rst, 0, maintenant()).effacer);

    // La reprise par `connect`.
    let (mut c, mut f) = paire_ts();
    c.fermer_envoi();
    calmer(&mut c, &mut f);
    f.fermer_envoi();
    calmer(&mut c, &mut f);
    let a = c.en_attente(false);
    let t0 = maintenant();
    // Un port de `bind` : sans délai, et même hors de la boucle.
    assert!(a.reprise(true, false, t0).is_some());
    // Un port de `connect` : par la boucle, après une seconde.
    assert!(a.reprise(false, true, t0).is_none());
    assert!(a.reprise(false, true, t0 + 1000 * MS).is_none());
    assert!(a.reprise(false, true, t0 + 1000 * MS + 1).is_some());
    assert!(a.reprise(false, false, t0 + 2000 * MS).is_none());
    // Le numéro initial : loin devant tout ce que l'ancienne a envoyé.
    assert_eq!(a.reprise(true, false, t0).unwrap().0, a.snd_nxt.wrapping_add(65_537));
    // Sans horodatages : jamais.
    let (mut c, mut f) = paire();
    c.fermer_envoi();
    calmer(&mut c, &mut f);
    f.fermer_envoi();
    calmer(&mut c, &mut f);
    assert!(c.en_attente(false).reprise(true, true, t0 + 9000 * MS).is_none());
}

fn syn_ts(s: Tcp, val: u32) -> Tcp {
    Tcp { options: tcp::Options { horodatage: Some((val, 0)), ..Default::default() }, ..s }
}

/// TCP_MAXSEG borne ce qu'annonce le SYN (`tcp_mss_clamp`) et le MSS d'envoi, y
/// compris pour une fille, qui en hérite de son écoute.
#[test]
fn tcp_maxseg_dans_le_syn_et_a_l_envoi() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.mss_utilisateur = 1000;
    let (syn, _) = sortants(&mut c)[0];
    assert_eq!(syn.options.mss, Some(1000));
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    f.poser_mss_utilisateur(800);
    let (sa, _) = sortants(&mut f)[0];
    assert_eq!(sa.options.mss, Some(800));
    c.recevoir(&sa, vide(), maintenant());
    livrer(&mut c, &mut f);
    assert_eq!((c.mss(), f.mss()), (800, 800));
}

/// Une paire qui a négocié SACK.
fn paire_sack(ts: bool) -> (Connexion, Connexion) {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 1 << 20, 1 << 20, ECHELLE);
    c.proposer_sack();
    if ts {
        c.proposer_horodatages(1_000_000);
    }
    let (syn, _) = sortants(&mut c)[0];
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 1 << 20, 1 << 20, ECHELLE);
    f.decalage_horodatages(5_000_000);
    let s = sortants(&mut f);
    c.recevoir(&s[0].0, vide(), maintenant());
    livrer(&mut c, &mut f);
    (c, f)
}

/// Des blocs vus d'un segment.
fn blocs(h: &Tcp) -> Vec<(u32, u32)> {
    h.options.blocs[..h.options.nb_blocs as usize].to_vec()
}

/// Le SYN propose, l'autre répond : SACK en service seulement si les deux le
/// disent ; TCPI_OPT_SACK.
#[test]
fn sack_negocie() {
    let (c, f) = paire_sack(false);
    assert_eq!((c.info(maintenant()).options & 2, f.info(maintenant()).options & 2), (2, 2));
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.proposer_sack();
    let (syn, _) = sortants(&mut c)[0];
    assert!(syn.options.sack_permis);
    let sans = Tcp { options: tcp::Options { sack_permis: false, ..syn.options }, ..syn };
    let mut f = Connexion::depuis_syn(&sans, 7000, MSS, 131_072, 16_384, ECHELLE);
    let (sa, _) = sortants(&mut f)[0];
    assert!(!sa.options.sack_permis);
    c.recevoir(&sa, vide(), maintenant());
    assert_eq!(c.info(maintenant()).options & 2, 0);
}

/// Le récepteur (`tcp_sack_new_ofo_skb`, `tcp_sack_maybe_coalesce`,
/// `tcp_sack_remove`) : le bloc le plus récent en tête, la fusion, au plus 4
/// (3 avec les horodatages), retirés quand RCV.NXT les passe.
#[test]
fn blocs_du_recepteur() {
    let (mut c, _f) = paire_sack(false);
    let n = bord(&c);
    let m = Tcp { drapeaux: tcp::ACK, ack: c.numeros().0, fenetre: 1000, ..Tcp::default() };
    let d = |i: u32| n.wrapping_add(100 * i);
    // Le quatrième ACK dupliqué d'un même RCV.NXT est comprimé : on laisse son
    // minuteur tomber, le contenu des blocs seul compte ici.
    let ack = |c: &mut Connexion| {
        let s = sortants(c);
        if !s.is_empty() {
            return s;
        }
        avancer(c.echeance().unwrap() - maintenant());
        c.minuteur(maintenant());
        sortants(c)
    };
    let recoit = |c: &mut Connexion, i: u32| {
        c.recevoir(&Tcp { seq: d(i), ..m }, Octets(vec![1; 50], 0), maintenant());
        sortants(c)
    };
    // Un trou : un bloc, et l'ACK du bord.
    let s = recoit(&mut c, 1);
    assert_eq!(s[0].0.ack, n);
    assert_eq!(blocs(&s[0].0), [(d(1), d(1) + 50)]);
    // Un autre plus loin, en tête.
    let s = recoit(&mut c, 3);
    assert_eq!(blocs(&s[0].0), [(d(3), d(3) + 50), (d(1), d(1) + 50)]);
    // Un bloc touché remonte, grandi.
    c.recevoir(&Tcp { seq: d(1) + 50, ..m }, Octets(vec![1; 50], 0), maintenant());
    let s = sortants(&mut c);
    assert_eq!(blocs(&s[0].0), [(d(1), d(2)), (d(3), d(3) + 50)]);
    // Celui qui comble l'écart : fusion en un seul.
    c.recevoir(&Tcp { seq: d(2), ..m }, Octets(vec![1; 100], 0), maintenant());
    let s = ack(&mut c);
    assert_eq!(blocs(&s[0].0), [(d(1), d(3) + 50)]);
    // Le trou comblé : plus de blocs, tout reçu.
    c.recevoir(&Tcp { seq: n, ..m }, Octets(vec![1; 100], 0), maintenant());
    let s = sortants(&mut c);
    assert_eq!(s[0].0.ack, d(3) + 50);
    assert!(blocs(&s[0].0).is_empty());
    // Sans horodatages, 4 blocs tiennent ; avec, 3, et ce n'est pas plus de 40
    // octets d'options.
    for (ts, attendus) in [(false, 4), (true, 3)] {
        let (mut c, _f) = paire_sack(ts);
        let n = bord(&c);
        let un = c.numeros().0;
        let val = c.info(maintenant()).etat as u32;
        let _ = val;
        for i in 1..=5u32 {
            let h = Tcp { drapeaux: tcp::ACK, seq: n.wrapping_add(100 * i), ack: un, fenetre: 1000, ..Tcp::default() };
            c.recevoir(&h, Octets(vec![1; 50], 0), maintenant());
            let s = sortants(&mut c);
            if i == 5 {
                let b = blocs(&s[0].0);
                assert_eq!(b.len(), attendus);
                assert_eq!(b[0].0, n.wrapping_add(500));
                assert!(tcp::longueur_entete(&s[0].0.options) <= 60);
            }
        }
    }
}

/// D-SACK (RFC 2883, `tcp_dsack_set`) : un doublon est dit en premier bloc, une
/// seule fois.
#[test]
fn dsack_du_recepteur() {
    let (mut c, _f) = paire_sack(false);
    let n = bord(&c);
    let m = Tcp { drapeaux: tcp::ACK, ack: c.numeros().0, fenetre: 1000, ..Tcp::default() };
    c.recevoir(&Tcp { seq: n, ..m }, Octets(vec![1; 100], 0), maintenant());
    let _ = sortants(&mut c);
    // Déjà reçu : le premier bloc le dit, sous l'ACK.
    c.recevoir(&Tcp { seq: n, ..m }, Octets(vec![1; 100], 0), maintenant());
    let s = sortants(&mut c);
    assert_eq!(s[0].0.ack, n.wrapping_add(100));
    assert_eq!(blocs(&s[0].0), [(n, n.wrapping_add(100))]);
    // Le segment suivant ne le redit pas.
    c.recevoir(&Tcp { seq: n.wrapping_add(100), ..m }, Octets(vec![1; 10], 0), maintenant());
    let s = sortants(&mut c);
    assert!(s.is_empty() || blocs(&s[0].0).is_empty());
    // À cheval : seulement ce qui est déjà reçu.
    let n = bord(&c);
    c.recevoir(&Tcp { seq: n.wrapping_sub(5), ..m }, Octets(vec![1; 10], 0), maintenant());
    let s = sortants(&mut c);
    assert_eq!(blocs(&s[0].0), [(n.wrapping_sub(5), n)]);
    // Un doublon hors d'ordre : le premier bloc dans le deuxième (RFC 2883 4.2).
    let n = bord(&c);
    let loin = n.wrapping_add(1000);
    c.recevoir(&Tcp { seq: loin, ..m }, Octets(vec![1; 100], 0), maintenant());
    let _ = sortants(&mut c);
    c.recevoir(&Tcp { seq: loin, ..m }, Octets(vec![1; 100], 0), maintenant());
    let s = sortants(&mut c);
    assert_eq!(blocs(&s[0].0), [(loin, loin.wrapping_add(100)), (loin, loin.wrapping_add(100))]);
}

/// Les trois premiers ACK dupliqués d'un même RCV.NXT partent ; puis ils sont
/// comprimés (`__tcp_ack_snd_check`) : un seul, peu après, ou le 44e.
#[test]
fn ack_dupliques_comprimes() {
    let (mut c, mut f) = paire_sack(false);
    // Une mesure du RTT, pour le délai de compression ; puis le mode « quickack »
    // du début consommé : il envoie chaque ACK.
    ecrire(&mut c, b"x");
    let s = sortants(&mut c);
    avancer(10 * MS);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    livrer(&mut f, &mut c);
    for _ in 0..16 {
        ecrire(&mut f, b"a");
        livrer(&mut f, &mut c);
        livrer(&mut c, &mut f);
    }
    let n = bord(&c);
    let m = Tcp { drapeaux: tcp::ACK, ack: c.numeros().0, fenetre: 1000, ..Tcp::default() };
    let recoit = |c: &mut Connexion, i: u32| {
        c.recevoir(&Tcp { seq: n.wrapping_add(100 * i), ..m }, Octets(vec![1; 50], 0), maintenant());
        sortants(c).len()
    };
    assert_eq!((recoit(&mut c, 1), recoit(&mut c, 2), recoit(&mut c, 3)), (1, 1, 1));
    assert_eq!(recoit(&mut c, 4), 0, "le quatrième attend");
    let e = c.echeance().unwrap();
    // 5 % du RTT du récepteur, pas encore mesuré ici : tout de suite ; au plus 1 ms.
    assert!(e <= maintenant() + MS);
    avancer(e - maintenant());
    c.minuteur(maintenant());
    assert_eq!(sortants(&mut c).len(), 1);
}

/// L'émetteur marque la file (`tcp_sacktag_write_queue`) : un segment dit arrivé
/// sort du vol ; un bloc faux est ignoré.
#[test]
fn tableau_de_l_emetteur() {
    let (mut c, _f) = paire_sack(false);
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 5 * MSS as usize]);
    assert_eq!(sortants(&mut c).len(), 5);
    let (una, nxt, _) = c.numeros();
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 65_535, ..Tcp::default() };
    let ack = |premier: u32, fin: u32| {
        let mut o = tcp::Options { nb_blocs: 1, ..Default::default() };
        o.blocs[0] = (premier, fin);
        Tcp { options: o, ..m }
    };
    // Le deuxième segment arrivé.
    c.recevoir(&ack(una + mss, una + 2 * mss), vide(), maintenant());
    assert_eq!(c.info(maintenant()).sackes, 1);
    // Redit : pas compté deux fois.
    c.recevoir(&ack(una + mss, una + 2 * mss), vide(), maintenant());
    assert_eq!(c.info(maintenant()).sackes, 1);
    // Un bloc qui coupe un segment : le segment entier seulement.
    c.recevoir(&ack(una + 2 * mss, una + 2 * mss + 10), vide(), maintenant());
    assert_eq!(c.info(maintenant()).sackes, 1);
    // Faux : au-delà de SND.NXT, à l'envers, sous SND.UNA.
    c.recevoir(&ack(una + mss, nxt + 1), vide(), maintenant());
    c.recevoir(&ack(una + 4 * mss, una + 3 * mss), vide(), maintenant());
    c.recevoir(&ack(una.wrapping_sub(100), una), vide(), maintenant());
    assert_eq!(c.info(maintenant()).sackes, 1);
    assert_eq!(c.info(maintenant()).phase, 1, "Disorder");
    // L'ACK cumulatif le couvre : plus de compte.
    c.recevoir(&Tcp { ack: una + 2 * mss, ..m }, vide(), maintenant());
    assert_eq!(c.info(maintenant()).sackes, 0);
}

/// RACK : trois segments arrivés après un trou (`sacked_out` >= `reordering`,
/// sans réordonnancement vu : fenêtre nulle) : la tête est perdue tout de suite,
/// et seule elle repart, pas ce qui est SACKé.
#[test]
fn rack_marque_le_trou() {
    let (mut c, mut f) = paire_sack(false);
    // Une mesure du RTT, de 10 ms.
    ecrire(&mut c, b"x");
    let s = sortants(&mut c);
    avancer(10 * MS);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    livrer(&mut f, &mut c);
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 5 * MSS as usize]);
    assert_eq!(sortants(&mut c).len(), 5);
    avancer(MS);
    let (una, _, _) = c.numeros();
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 65_535, ..Tcp::default() };
    let ack = |fin: u32| {
        let mut o = tcp::Options { nb_blocs: 1, ..Default::default() };
        o.blocs[0] = (una + mss, una + fin * mss);
        Tcp { options: o, ..m }
    };
    // Deux segments après le trou : rien encore.
    c.recevoir(&ack(3), vide(), maintenant());
    assert_eq!(c.info(maintenant()).perdus, 0);
    // Trois : le trou est perdu ; RTT, c'est-à-dire 1 ms depuis l'envoi, ne suffit
    // pas encore pour la fenêtre nulle : `rack.rtt` vaut 1 ms, il faut l'écoulé.
    avancer(MS);
    c.recevoir(&ack(4), vide(), maintenant());
    let i = c.info(maintenant());
    assert_eq!((i.perdus, i.phase), (1, 3), "le trou perdu, la reprise");
    let s = sortants(&mut c);
    assert_eq!(s[0].0.seq, una);
    assert_eq!(s[0].1.len(), MSS as usize, "la tête seule, renvoyée");
    assert!(s.iter().skip(1).all(|x| !t::avant(x.0.seq, una + 4 * mss)), "rien de SACKé ne repart");
    // Un ACK qui couvre tout : la reprise finie, sans attendre au-delà de
    // `high_seq` (SACK n'a pas ce souci).
    let (_, nxt, _) = c.numeros();
    c.recevoir(&Tcp { ack: nxt, ..m }, vide(), maintenant());
    assert_eq!(c.info(maintenant()).phase, 0);
}

/// Un trou comblé par un segment jamais renvoyé : du réordonnancement
/// (`tcp_check_sack_reordering`) : le degré grandit, la fenêtre de RACK s'ouvre.
#[test]
fn reordonnancement_vu() {
    let (mut c, mut f) = paire_sack(false);
    ecrire(&mut c, b"x");
    let s = sortants(&mut c);
    avancer(10 * MS);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    livrer(&mut f, &mut c);
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 8 * MSS as usize]);
    sortants(&mut c);
    let (una, _, _) = c.numeros();
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 65_535, ..Tcp::default() };
    let mut o = tcp::Options { nb_blocs: 1, ..Default::default() };
    o.blocs[0] = (una + 4 * mss, una + 6 * mss);
    c.recevoir(&Tcp { options: o, ..m }, vide(), maintenant());
    let avant = c.info(maintenant()).reord_seen;
    // Le cinquième avant le deuxième : un bloc plus bas, jamais renvoyé.
    o.blocs[0] = (una + 3 * mss, una + 6 * mss);
    c.recevoir(&Tcp { options: o, ..m }, vide(), maintenant());
    let i = c.info(maintenant());
    assert_eq!(i.reord_seen, avant + 1);
    assert_eq!(i.reordonnancement, 3);
    // Plus loin encore, un écart plus grand que le degré : il grandit.
    o.blocs[0] = (una + mss, una + 6 * mss);
    c.recevoir(&Tcp { options: o, ..m }, vide(), maintenant());
    assert!(c.info(maintenant()).reordonnancement >= 5);
}

/// Le bord gauche tombe sur du SACKé : l'autre a peut-être oublié. Le RTO est
/// avancé (`tcp_check_sack_reneging`) ; s'il tombe, les SACK sont oubliés
/// (`tcp_timeout_mark_lost`), et tout repart.
#[test]
fn sack_renie() {
    let (mut c, mut f) = paire_sack(false);
    ecrire(&mut c, b"x");
    let s = sortants(&mut c);
    avancer(100 * MS);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    livrer(&mut f, &mut c);
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 4 * MSS as usize]);
    sortants(&mut c);
    let (una, _, _) = c.numeros();
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 65_535, ..Tcp::default() };
    let mut o = tcp::Options { nb_blocs: 1, ..Default::default() };
    o.blocs[0] = (una + 2 * mss, una + 3 * mss);
    c.recevoir(&Tcp { options: o, ..m }, vide(), maintenant());
    assert_eq!(c.info(maintenant()).sackes, 1);
    // L'ACK avance jusqu'au segment SACKé, sans le couvrir : `reneging`.
    c.recevoir(&Tcp { ack: una + 2 * mss, options: o, ..m }, vide(), maintenant());
    let e = c.echeance().unwrap();
    assert!(e - maintenant() <= 60 * MS, "le RTO avancé : la moitié du RTT");
    avancer(e - maintenant());
    c.minuteur(maintenant());
    let i = c.info(maintenant());
    assert_eq!((i.sackes, i.phase), (0, 4), "les SACK oubliés, Loss");
    assert_eq!(i.perdus, 2);
}

/// Les segments portent leurs blocs à la place de leur charge (`tcp_current_mss`).
#[test]
fn les_blocs_prennent_la_place_de_la_charge() {
    let (mut c, _f) = paire_sack(false);
    let n = bord(&c);
    let m = Tcp { drapeaux: tcp::ACK, ack: c.numeros().0, fenetre: 65_535, ..Tcp::default() };
    c.recevoir(&Tcp { seq: n.wrapping_add(1000), ..m }, Octets(vec![1; 50], 0), maintenant());
    let _ = sortants(&mut c);
    ecrire(&mut c, &vec![1u8; 3000]);
    let s = sortants(&mut c);
    assert_eq!(s[0].1.len(), MSS as usize - 12, "un bloc : 4 + 8 octets");
    assert_eq!(blocs(&s[0].0).len(), 1);
}

/// Une paire avec SACK, et une mesure du RTT de 10 ms (le SRTT part de la poignée
/// de main, à l'heure 0 : il en prend un huitième).
fn paire_sack_rtt() -> (Connexion, Connexion) {
    let (mut c, mut f) = paire_sack(false);
    ecrire(&mut c, b"x");
    let s = sortants(&mut c);
    avancer(10 * MS);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    livrer(&mut f, &mut c);
    let _ = lire(&mut f, 1);
    (c, f)
}

/// TLP : la dernière salve sans réponse. Après 2 × SRTT + 2 ms (arrondis au
/// jiffy), le dernier segment repart, sans toucher au RTO reculé ni à la cwnd
/// (`tcp_schedule_loss_probe`, `tcp_send_loss_probe`).
#[test]
fn tlp_renvoie_le_dernier() {
    let (mut c, _f) = paire_sack_rtt();
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 3 * MSS as usize]);
    assert_eq!(sortants(&mut c).len(), 3);
    let (una, nxt, _) = c.numeros();
    let cwnd = c.congestion().0;
    // 2 × SRTT + 2 ms, arrondis au jiffy (4 ms : HZ = 250).
    let e = c.echeance().unwrap();
    let srtt = c.info(maintenant()).rtt as u64 * 1000;
    assert_eq!(e - maintenant(), (2 * srtt + 2 * MS).div_ceil(4 * MS) * 4 * MS);
    avancer(e - maintenant());
    c.minuteur(maintenant());
    let s = sortants(&mut c);
    assert_eq!(s.iter().map(|x| x.0.seq).collect::<Vec<_>>(), [una + 2 * mss]);
    let i = c.info(maintenant());
    assert_eq!((i.phase, i.total_rto, i.retransmis, i.cwnd), (0, 0, 0, cwnd));
    assert_eq!(c.numeros().1, nxt);
    // Une seule à la fois : le suivant est le RTO, du dernier envoi.
    let e = c.echeance().unwrap();
    assert!(e - maintenant() > 100 * MS);
    // L'ACK du tout, d'un seul coup : la perte est réparée ; la cwnd réduit (CWR :
    // `tcp_process_tlp_ack` le voit à un ACK qui passe la sonde), sans reprise.
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: nxt, fenetre: 65_535, ..Tcp::default() };
    c.recevoir(&m, vide(), maintenant());
    assert_eq!(c.info(maintenant()).phase, 0);
    ecrire(&mut c, b"y");
    sortants(&mut c);
    c.recevoir(&Tcp { ack: nxt.wrapping_add(1), ..m }, vide(), maintenant());
    assert!(c.congestion().0 < cwnd, "{} contre {}", c.congestion().0, cwnd);
    assert_eq!(c.info(maintenant()).phase, 0);
}

/// Un seul segment en vol : la sonde attend aussi un ACK retardé possible (200 ms),
/// bornée par le RTO. Sans SACK : pas de sonde.
#[test]
fn tlp_un_seul_segment_et_sans_sack() {
    let (mut c, _f) = paire_sack_rtt();
    ecrire(&mut c, b"x");
    sortants(&mut c);
    let attente = c.echeance().unwrap() - maintenant();
    assert_eq!(attente, c.congestion().2.div_ceil(4 * MS) * 4 * MS, "le RTO la borne : il est de 210 ms");
    let (mut c, mut f) = paire();
    ecrire(&mut c, b"x");
    let s = sortants(&mut c);
    avancer(10 * MS);
    f.recevoir(&s[0].0, Octets(s[0].1.clone(), 0), maintenant());
    livrer(&mut f, &mut c);
    ecrire(&mut c, b"y");
    sortants(&mut c);
    assert_eq!(c.echeance().unwrap() - maintenant(), c.congestion().2);
}

/// La sonde préfère un segment neuf, hors de la cwnd (`push_one = 2`).
#[test]
fn tlp_prefere_du_neuf() {
    let (mut c, _f) = paire_sack_rtt();
    let cwnd = c.congestion().0 as usize;
    ecrire(&mut c, &vec![1u8; (cwnd + 1) * MSS as usize]);
    assert_eq!(sortants(&mut c).len(), cwnd);
    let nxt = c.numeros().1;
    avancer(c.echeance().unwrap() - maintenant());
    c.minuteur(maintenant());
    let s = sortants(&mut c);
    assert_eq!(s.iter().map(|x| x.0.seq).collect::<Vec<_>>(), [nxt]);
    assert_eq!(c.numeros().1, nxt.wrapping_add(MSS as u32));
    assert_eq!(c.info(maintenant()).phase, 0);
}

/// La sonde et l'original sont arrivés : le D-SACK de la sonde dit qu'il n'y avait
/// rien de perdu : la cwnd reste.
#[test]
fn tlp_rien_de_perdu() {
    let (mut c, _f) = paire_sack_rtt();
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 3 * MSS as usize]);
    sortants(&mut c);
    let (una, nxt, _) = c.numeros();
    let cwnd = c.congestion().0;
    avancer(c.echeance().unwrap() - maintenant());
    c.minuteur(maintenant());
    sortants(&mut c);
    let mut o = tcp::Options { nb_blocs: 1, ..Default::default() };
    o.blocs[0] = (una + 2 * mss, nxt);
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: nxt, fenetre: 65_535, options: o, ..Tcp::default() };
    c.recevoir(&m, vide(), maintenant());
    ecrire(&mut c, b"y");
    sortants(&mut c);
    c.recevoir(&Tcp { ack: nxt.wrapping_add(1), options: tcp::Options::default(), ..m }, vide(), maintenant());
    assert!(c.congestion().0 >= cwnd);
}

/// F-RTO (RFC 5682) : un RTO pour rien. La tête repart ; l'ACK qui avance fait
/// envoyer du NEUF, pas tout le reste ; et un ACK de segments jamais renvoyés dit
/// que tout était arrivé : la perte est annulée, la cwnd et le seuil reviennent.
/// Sans SACK ni horodatages : c'est le cas de slirp.
#[test]
fn frto_un_rto_pour_rien() {
    let (mut c, _f) = paire();
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 8 * MSS as usize]);
    let s = sortants(&mut c);
    let cwnd = c.congestion().0 as usize;
    assert_eq!(s.len(), cwnd.min(8));
    let (una, nxt, _) = c.numeros();
    let avant_rto = c.congestion().0;
    echeance_suivante(&mut c);
    let s = sortants(&mut c);
    assert_eq!(s.iter().map(|x| x.0.seq).collect::<Vec<_>>(), [una]);
    assert_eq!(c.info(maintenant()).phase, 4);
    assert!(c.congestion().0 <= 2);
    // L'ACK du renvoi : pas de renvoi de plus, mais du neuf, s'il y en a.
    ecrire(&mut c, &vec![2u8; 4 * MSS as usize]);
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una + mss, fenetre: 65_535, ..Tcp::default() };
    c.recevoir(&m, vide(), maintenant());
    let s = sortants(&mut c);
    assert!(!s.is_empty() && s.iter().all(|x| !t::avant(x.0.seq, nxt)), "du neuf seulement : {:?}", s.iter().map(|x| x.0.seq - una).collect::<Vec<_>>());
    // Un ACK des segments jamais renvoyés : la perte n'en était pas une.
    let i = c.info(maintenant());
    assert_eq!(i.perdus, cwnd.min(8) as u32 - 1);
    c.recevoir(&Tcp { ack: una + 3 * mss, ..m }, vide(), maintenant());
    let i = c.info(maintenant());
    assert_eq!((i.phase, i.perdus), (0, 0), "annulée");
    assert!(c.congestion().0 >= avant_rto);
}

/// F-RTO : un ACK dupliqué après le neuf : la perte était vraie, on renvoie.
#[test]
fn frto_une_vraie_perte() {
    let (mut c, _f) = paire();
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 8 * MSS as usize]);
    sortants(&mut c);
    let (una, nxt, _) = c.numeros();
    echeance_suivante(&mut c);
    sortants(&mut c);
    ecrire(&mut c, &vec![2u8; 4 * MSS as usize]);
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una + mss, fenetre: 65_535, ..Tcp::default() };
    c.recevoir(&m, vide(), maintenant());
    assert!(sortants(&mut c).iter().all(|x| !t::avant(x.0.seq, nxt)));
    // L'ACK dupliqué : les segments neufs sont arrivés, pas les autres.
    c.recevoir(&m, vide(), maintenant());
    let s = sortants(&mut c);
    assert_eq!(s[0].0.seq, una + mss, "le renvoi repart");
    assert_eq!(c.info(maintenant()).phase, 4);
}

/// L'annulation par les horodatages : la reprise a renvoyé la tête, mais l'ACK
/// répond à un envoi antérieur à ce renvoi : le segment n'était que retardé.
#[test]
fn annulation_par_tsecr() {
    let (mut c, mut f) = paire_ts();
    calmer(&mut c, &mut f);
    avancer(100 * MS);
    let mss = MSS as u32 - 12;
    ecrire(&mut c, &vec![1u8; 6 * mss as usize]);
    let s = sortants(&mut c);
    let (val0, recent) = s[0].0.options.horodatage.unwrap();
    let (una, nxt, _) = c.numeros();
    let (cwnd, seuil, _) = c.congestion();
    avancer(10 * MS);
    // Trois ACK dupliqués : la reprise, la tête renvoyée. (Le premier met à jour la
    // fenêtre : il ne compte pas.)
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 65_535, options: tcp::Options { horodatage: Some((recent, val0)), ..Default::default() }, ..Tcp::default() };
    for _ in 0..4 {
        c.recevoir(&m, vide(), maintenant());
    }
    assert_eq!(c.info(maintenant()).phase, 3);
    let s = sortants(&mut c);
    assert_eq!(s[0].0.seq, una);
    assert!(c.congestion().0 < cwnd);
    assert!(c.congestion().1 < seuil);
    // L'ACK de tout : son écho précède le renvoi : la reprise est défaite, le seuil
    // revient. (Sans SACK, l'état reste jusqu'à un ACK qui passe `high_seq`, et PRR
    // règle la cwnd jusque-là, comme chez Linux ; le seuil revenu, elle remonte
    // en démarrage lent.)
    avancer(10 * MS);
    c.recevoir(&Tcp { ack: nxt, ..m }, vide(), maintenant());
    assert_eq!(c.congestion().1, seuil);
    ecrire(&mut c, b"x");
    sortants(&mut c);
    c.recevoir(&Tcp { ack: nxt.wrapping_add(1), ..m }, vide(), maintenant());
    assert_eq!(c.info(maintenant()).phase, 0);
    assert_eq!(c.congestion().1, seuil);
}

/// L'annulation par D-SACK : le seul renvoi de la reprise est démenti par un
/// doublon : la réduction était pour rien.
#[test]
fn annulation_par_dsack() {
    let (mut c, _f) = paire_sack_rtt();
    let mss = MSS as u32;
    ecrire(&mut c, &vec![1u8; 6 * MSS as usize]);
    sortants(&mut c);
    let (una, nxt, _) = c.numeros();
    let (cwnd, seuil, _) = c.congestion();
    avancer(MS);
    let m = Tcp { drapeaux: tcp::ACK, seq: bord(&c), ack: una, fenetre: 65_535, ..Tcp::default() };
    let mut o = tcp::Options { nb_blocs: 1, ..Default::default() };
    o.blocs[0] = (una + mss, una + 5 * mss);
    c.recevoir(&Tcp { options: o, ..m }, vide(), maintenant());
    assert_eq!(c.info(maintenant()).phase, 3);
    let s = sortants(&mut c);
    assert_eq!(s[0].0.seq, una);
    assert!(c.congestion().0 < cwnd);
    // L'ACK de tout, et le D-SACK de la tête : son renvoi était un doublon.
    let mut o = tcp::Options { nb_blocs: 1, ..Default::default() };
    o.blocs[0] = (una, una + mss);
    c.recevoir(&Tcp { ack: nxt, options: o, ..m }, vide(), maintenant());
    let (cwnd2, seuil2, _) = c.congestion();
    assert_eq!(c.info(maintenant()).phase, 0);
    assert_eq!(c.info(maintenant()).dsack_doublons, 1);
    assert!(cwnd2 >= cwnd && seuil2 == seuil, "{cwnd2} contre {cwnd}, seuil {seuil2} contre {seuil}");
}

/// Un SYN renvoyé pour rien : l'écho est celui du premier : la fenêtre de départ
/// reste de 10 (`tcp_try_undo_spurious_syn`) ; renvoyé deux fois et sans cet écho :
/// 1 (`tcp_init_transfer`).
#[test]
fn syn_renvoye_pour_rien() {
    for (ecart, attendu) in [(0, 10), (1, 1)] {
        avancer(10 * MS);
        let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
        c.proposer_horodatages(1000);
        let (syn, _) = sortants(&mut c)[0];
        let val = syn.options.horodatage.unwrap().0;
        for _ in 0..2 {
            echeance_suivante(&mut c);
            let _ = sortants(&mut c);
        }
        let sa = Tcp { source: 80, destination: 40000, seq: 7000, ack: 1001, drapeaux: tcp::SYN | tcp::ACK, fenetre: 65_535,
                       options: tcp::Options { mss: Some(MSS), horodatage: Some((5, val + ecart)), ..Default::default() }, ..Tcp::default() };
        c.recevoir(&sa, vide(), maintenant());
        assert_eq!(c.etat(), Etat::Etablie);
        assert_eq!(c.congestion().0, attendu);
    }
}

/// Une fille établie, sans échange ; RCV.NXT : le second membre.
fn fille_etablie(rcvbuf: usize) -> (Connexion, u32) {
    let syn = Tcp { source: 40000, destination: 80, seq: 1000, drapeaux: tcp::SYN, fenetre: 65535, options: tcp::Options { mss: Some(1460), sack_permis: true, echelle: Some(7), ..tcp::Options::default() }, ..Tcp::default() };
    let mut f = Connexion::depuis_syn(&syn, 7000, 1460, rcvbuf, 16_384, 7);
    sortants(&mut f);
    f.recevoir(&Tcp { seq: 1001, ack: 7001, drapeaux: tcp::ACK, fenetre: 1000, options: tcp::Options::default(), ..syn }, vide(), maintenant());
    assert_eq!(f.etat(), Etat::Etablie);
    (f, 1001)
}

/// Des données au-delà du FIN, en CLOSE_WAIT : le RST de `tcp_rcv_state_process` (RCV_SHUTDOWN, posé
/// par `tcp_fin`), et rien de plus à lire.
#[test]
fn des_donnees_apres_le_fin() {
    let (mut f, s) = fille_etablie(131_072);
    let m = Tcp { source: 40000, destination: 80, ack: 7001, fenetre: 1000, ..Tcp::default() };
    f.recevoir(&Tcp { seq: s, drapeaux: tcp::ACK | tcp::FIN, ..m }, vide(), maintenant());
    assert_eq!(f.etat(), Etat::AttenteFermeture);
    sortants(&mut f);
    f.recevoir(&Tcp { seq: s, drapeaux: tcp::ACK, ..m }, Octets(vec![1; 100], 0), maintenant());
    assert_eq!(f.lisibles(), 0, "des octets lisibles apres la fin de l'autre");
    assert!(sortants(&mut f).iter().any(|(h, _)| h.drapeaux & tcp::RST != 0));
    assert_eq!(f.etat(), Etat::Fermee);
}

/// SYN_SENT : un RST|ACK ne reçoit jamais de RST, même avec un TSecr faux ; un ACK faux, si, et
/// le SYN repart vite pour nettoyer ce qui reste de l'ancienne connexion.
#[test]
fn syn_envoye_pas_de_rst_pour_un_rst() {
    let mut c = Connexion::connecter(40000, 80, 5000, 1460, 131_072, 16_384, 7);
    c.proposer_horodatages(0);
    sortants(&mut c);
    let m = Tcp { source: 80, destination: 40000, seq: 9, fenetre: 65535, ..Tcp::default() };
    let faux = tcp::Options { horodatage: Some((1, 12_345)), ..tcp::Options::default() };
    c.recevoir(&Tcp { ack: 5001, drapeaux: tcp::RST | tcp::ACK, options: faux, ..m }, vide(), maintenant());
    assert!(sortants(&mut c).iter().all(|(h, _)| h.drapeaux & tcp::RST == 0), "un RST repond a un RST");
    assert_eq!(c.etat(), Etat::SynEnvoye);
    c.recevoir(&Tcp { ack: 4000, drapeaux: tcp::ACK, ..m }, vide(), maintenant());
    assert!(sortants(&mut c).iter().any(|(h, _)| h.drapeaux & tcp::RST != 0 && h.seq == 4000));
    assert_eq!(c.etat(), Etat::SynEnvoye);
    avancer(8 * MS);
    c.minuteur(maintenant());
    assert!(sortants(&mut c).iter().any(|(h, _)| h.drapeaux & tcp::SYN != 0), "le SYN repart sans attendre la seconde");
}

/// TCP_MAXSEG borne ce qu'on annonce, dès le SYN, et tout ce qui en découle (`tcp_mss_clamp`).
#[test]
fn tcp_maxseg_borne_advmss() {
    let mut c = Connexion::connecter(40000, 80, 5000, 65_495, 131_072, 16_384, 7);
    c.mss_utilisateur = 1200;
    let s = sortants(&mut c);
    assert_eq!(s[0].0.options.mss, Some(1200));
    let sa = Tcp { source: 80, destination: 40000, seq: 9, ack: 5001, drapeaux: tcp::SYN | tcp::ACK, fenetre: 65535, options: tcp::Options { mss: Some(1460), ..tcp::Options::default() }, ..Tcp::default() };
    c.recevoir(&sa, vide(), maintenant());
    assert_eq!(c.info(maintenant()).advmss, 1200);
}

/// Un trou comblé, seul un FIN attendait derrière : l'ACK part sans attendre.
#[test]
fn le_fin_derriere_un_trou() {
    let (mut f, s) = fille_etablie(131_072);
    let m = Tcp { source: 40000, destination: 80, ack: 7001, fenetre: 1000, ..Tcp::default() };
    f.recevoir(&Tcp { seq: s.wrapping_add(10), drapeaux: tcp::ACK | tcp::FIN, ..m }, vide(), maintenant());
    sortants(&mut f);
    f.recevoir(&Tcp { seq: s, drapeaux: tcp::ACK, ..m }, Octets(vec![1; 10], 0), maintenant());
    assert_eq!(f.etat(), Etat::AttenteFermeture);
    let a = sortants(&mut f);
    assert_eq!(a.last().map(|(h, _)| h.ack), Some(s.wrapping_add(11)));
}

/// Un segment hors d'ordre jeté faute de mémoire ne doit pas s'annoncer par un SACK : l'émetteur le
/// croirait arrivé et ne le renverrait pas.
#[test]
fn un_segment_jete_ne_s_annonce_pas() {
    let (mut f, s) = fille_etablie(16_384);
    f.rcvbuf_fixe = true;
    let m = Tcp { source: 40000, destination: 80, ack: 7001, drapeaux: tcp::ACK, fenetre: 1000, ..Tcp::default() };
    for i in 1..200u32 {
        f.recevoir(&Tcp { seq: s + i * 2000, ..m }, Octets(vec![1; 1000], 0), maintenant());
        for (x, _) in sortants(&mut f) {
            for b in &x.options.blocs[..x.options.nb_blocs as usize] {
                assert!(t::apres(b.1, s), "{b:?}");
                assert!(f.memoire_hors_ordre() > 0, "un bloc annonce, rien de garde");
            }
        }
    }
    assert!(f.memoire_hors_ordre() <= 2 * f.rcvbuf + 4096, "{}", f.memoire_hors_ordre());
}

/// TCP_QUICKACK : l'état vivant, relu ; 1 fait partir l'ACK dû ; une valeur paire revient ensuite
/// au ping-pong (`__tcp_sock_set_quickack`).
#[test]
fn tcp_quickack_vivant() {
    let (mut c, mut f) = paire();
    calmer(&mut c, &mut f);
    assert!(f.hors_du_ping_pong());
    f.quickack(false);
    assert!(!f.hors_du_ping_pong());
    ecrire(&mut c, b"bonjour");
    livrer(&mut c, &mut f);
    assert!(sortants(&mut f).is_empty(), "en ping-pong, l'ACK attend");
    // (`tcp_cleanup_rbuf` : pas d'ACK anticipé tant que la file de lecture n'est pas vide.)
    f.lire::<()>(7, false, |o| Ok(o.len())).unwrap();
    assert!(sortants(&mut f).is_empty(), "en ping-pong, lire ne le fait pas partir");
    let e = f.quickack_valeur(2, maintenant());
    assert!(e.a_emettre);
    assert_eq!(sortants(&mut f).len(), 1, "l'ACK du part");
    assert!(!f.hors_du_ping_pong(), "une valeur paire revient au ping-pong");
    f.quickack_valeur(1, maintenant());
    assert!(f.hors_du_ping_pong());
}

/// SO_ERROR dit aussi l'erreur douce, une fois.
#[test]
fn so_error_prend_l_erreur_douce() {
    let (mut c, _) = paire();
    let una = c.numeros().0;
    c.erreur_icmp(113, una, true, false, maintenant());
    assert_eq!(c.erreur(), 0);
    assert_eq!(c.prendre_erreur_so(), 113);
    assert_eq!(c.prendre_erreur_so(), 0);
}

/// `close` avec des données non lues : un RST en tout état, même LAST_ACK ; `tcp_disconnect`, lui, n'en
/// veut en LAST_ACK que s'il reste à envoyer.
#[test]
fn le_rst_des_donnees_non_lues() {
    let (mut c, mut f) = paire();
    calmer(&mut c, &mut f);
    ecrire(&mut f, b"abc");
    f.fermer_envoi();
    livrer(&mut f, &mut c);
    c.fermer_envoi();
    assert_eq!(c.etat(), Etat::DernierAck);
    assert_eq!(c.deconnexion(), (true, true), "le FIN n'est pas encore parti : RST et erreur");
    sortants(&mut c);
    assert_eq!(c.deconnexion(), (false, false), "tout est parti : ni RST ni erreur");
    assert!(c.avorter_sur_donnees().a_emettre);
    assert!(sortants(&mut c).iter().any(|(h, _)| h.drapeaux & tcp::RST != 0));
    assert_eq!(c.etat(), Etat::Fermee);
}

/// `tcp_disconnect`, selon l'état.
#[test]
fn deconnexion_selon_l_etat() {
    let (mut c, _f) = paire();
    assert_eq!(c.deconnexion(), (true, true));
    let s = Connexion::connecter(40000, 80, 5000, 1460, 131_072, 16_384, 7);
    assert_eq!(s.deconnexion(), (false, true), "SYN_SENT : l'erreur, sans RST");
    c.avorter();
    assert_eq!(c.deconnexion(), (false, false));
}
