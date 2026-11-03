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
    // `tcp_retries2` (15) : le temps modélisé, 924,6 s depuis l'envoi,
    // quinze retransmissions.
    assert_eq!(t::temps_modele(15, t::RTO_MIN) / MS, 924_600);
    assert_eq!(sans_reponse(|_| {}, false), (924_600, 15, t::ETIMEDOUT));
    // Une orpheline : 8 (`tcp_orphan_retries`), 102,2 s.
    assert_eq!(sans_reponse(|c| c.reglages.orpheline = true, false), (102_200, 8, t::ETIMEDOUT));
    // TCP_USER_TIMEOUT de 5 s : le dernier RTO raccourci pour tomber pile.
    assert_eq!(sans_reponse(|c| c.reglages.delai_utilisateur = 5000 * MS, false).0, 5000);
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
    // n'avance pas, l'ACK attend ; la lecture le fait partir.
    lire(&mut f, 100);
    calmer(&mut c, &mut f);
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
    let (mut c, mut f) = paire_avec(MSS, 16_384, 16_384);
    let _ = &mut c;
    let bord = bord(&f);
    let modele = Tcp { drapeaux: tcp::ACK, ack: c.numeros().0, fenetre: 65_535, ..Tcp::default() };
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
    let modele = Tcp { drapeaux: tcp::ACK, ack: c.numeros().0, fenetre: 65_535, ..Tcp::default() };
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
