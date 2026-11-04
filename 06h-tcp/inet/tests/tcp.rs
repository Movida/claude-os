//! Une connexion TCP, de la poignée de main à la fermeture (inet::tcp) :
//! deux connexions reliées par un lien parfait (ni perte ni désordre, ce
//! que font `lo` et slirp), puis des segments faits à la main pour chaque
//! règle de la RFC 9293 et de Linux.

use formats::reseau::tcp::{self, Tcp};
use inet::tcp::{self as t, Charge, Etat, Sortant, Tcb};
use std::cell::Cell;

// L'horloge des tests, en nanosecondes : elle n'avance que quand un test
// le demande (`avancer`), ou quand `calmer` laisse partir un ACK retardé.
thread_local! {
    static HEURE: Cell<u64> = const { Cell::new(0) };
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
/// ne fait ni un MSS ni le quart de SO_RCVBUF, la fenêtre ne s'ouvre pas ;
/// ensuite, si.
#[test]
fn pas_de_petite_fenetre() {
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 65_536, ECHELLE);
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 16_384, 16_384, ECHELLE);
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
    // s'achève, la fenêtre de congestion au seuil, la moitié de dix.
    let fin = livrer_sauf(&mut c, &mut f, renvoyes, &[]);
    assert!(fin.is_empty());
    assert_eq!(f.lisibles(), 10 * MSS as usize);
    assert_eq!((c.congestion().0, c.congestion().1), (5, 5));
    assert_eq!(c.non_acquittes(), 0);
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
    let una = c.numeros().0;
    c.erreur_icmp(113, una, true, false, maintenant());
    assert_eq!(c.congestion().2 / MS, 200);
    assert_eq!(c.echeance(), Some(t1 + c.congestion().2));
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
/// (Chez Linux, `rcv_ssthresh` borne aussi la fenêtre en régime établi :
/// nous n'avons pas cet ajustement de la réception, un écart écrit.)
#[test]
fn ack_au_deuxieme_segment_plein() {
    let (mut c, mut f) = paire_avec(MSS, 1 << 25, 1 << 20);
    for _ in 0..16 {
        ecrire(&mut c, b"a");
        livrer(&mut c, &mut f);
        livrer(&mut f, &mut c);
    }
    calmer(&mut c, &mut f);
    ecrire(&mut c, &vec![2u8; MSS as usize]);
    livrer(&mut c, &mut f);
    assert!(sortants(&mut f).is_empty());
    ecrire(&mut c, &vec![3u8; MSS as usize]);
    livrer(&mut c, &mut f);
    assert_eq!(sortants(&mut f).len(), 1);
}

/// La file hors d'ordre est bornée en taille vraie (deux fois SO_RCVBUF,
/// avec la file de réception) : un pair qui envoie des milliers de segments
/// d'un octet derrière un trou ne fait pas tout garder.
#[test]
fn file_hors_d_ordre_bornee() {
    let (_c, mut f) = paire_avec(MSS, 16_384, 16_384);
    let bord = bord(&f);
    let modele = Tcp { drapeaux: tcp::ACK, ack: f.numeros().0, fenetre: 65_535, ..Tcp::default() };
    for i in 1..4000u32 {
        f.recevoir(&Tcp { seq: bord.wrapping_add(i), ..modele }, Octets(vec![1], 0), maintenant());
    }
    assert!(f.memoire_reception() <= 2 * 16_384, "{}", f.memoire_reception());
    f.recevoir(&Tcp { seq: bord, ..modele }, Octets(vec![0], 0), maintenant());
    let n = f.lisibles();
    assert!(n > 1 && n < 4000, "{n} octets gardés");
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
    assert_eq!(t::echelle(131_072, false, 32 << 20), 10);
    assert_eq!(t::echelle(8 << 20, true, 32 << 20), 7);
    assert_eq!(t::echelle(131_072, false, 15 << 20), 8);
    assert_eq!(t::echelle(4096, true, 32 << 20), 0);
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
    // Libre : SO_SNDBUF agrandi à l'établissement ; sous pression, non.
    let (c, _f) = paire();
    assert!(c.sndbuf > 16_384);
    let mut c = Connexion::connecter(40000, 80, 1000, MSS, 131_072, 16_384, ECHELLE);
    c.memoire = t::Memoire::Pression;
    let syn = sortants(&mut c)[0].0;
    let mut f = Connexion::depuis_syn(&syn, 7000, MSS, 131_072, 16_384, ECHELLE);
    calmer(&mut c, &mut f);
    assert_eq!(c.sndbuf, 16_384);
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
