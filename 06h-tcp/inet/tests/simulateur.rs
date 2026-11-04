//! Le simulateur de TCP (plan de 6h) : deux connexions (inet::tcp) reliées
//! par un lien qui perd, duplique, retarde et réordonne au hasard, à
//! l'horloge simulée. slirp et `lo` ne perdent rien : sans lui, les
//! retransmissions, la reprise rapide, la file hors d'ordre, les sondes et
//! les abandons ne seraient jamais exercés.
//!
//! Chaque essai tire d'une graine : le lien (0 à 30 % de pertes, des
//! duplications, un délai et une gigue, qui réordonne), les quantités à
//! transférer dans chaque sens (de 0 à 8 Mio, 300 Ko au-delà de 10 % de
//! pertes), et le comportement des deux
//! programmes (des écritures et des lectures de tailles au hasard, des
//! pauses qui ferment la fenêtre). Chaque côté écrit tout, ferme son sens,
//! et lit jusqu'au FIN de l'autre.
//!
//! L'ORACLE est fait d'invariants, pas d'un résultat attendu :
//!   (a) ce qu'un côté lit est toujours la suite exacte de ce que l'autre a
//!       écrit : ni trou, ni doublon, ni octet changé (vérifié à chaque
//!       lecture) ; et un FIN n'est vu qu'après tout le reste ;
//!   (b) chaque essai finit, et jamais rien ne s'arrête : jusqu'à 10 % de
//!       pertes, avant une échéance calculée (deux fois le budget de
//!       `tcp_retries2`, plus la taille du transfert à 1 Kio/s) ; au-delà,
//!       sans jamais passer deux fois ce budget sans un progrès (un octet
//!       écrit ou lu, un changement d'état) : une connexion avance, ou
//!       abandonne. Le débit, lui, peut y tomber à quelques dizaines
//!       d'octets par seconde : sans horodatages, un ACK perdu puis redit
//!       bien plus tard par un segment de données de l'autre donne une
//!       mesure du RTT de plusieurs dizaines de secondes, et le RTO suit
//!       (Linux sans horodatages aussi) ;
//!       soit proprement (tout lu des deux côtés, les deux FIN, un côté en
//!       TIME_WAIT ou les deux), soit par une erreur (ETIMEDOUT, ECONNRESET,
//!       EPIPE), après laquelle l'autre côté ne croit jamais avoir tout reçu
//!       s'il ne l'a pas ;
//!   (c) jusqu'à 10 % de pertes, la fin propre est exigée (au-delà, une
//!       longue suite de pertes peut légitimement faire abandonner).
//! Une graine qui échoue est affichée, pour être rejouée seule
//! (`SIMULATEUR_GRAINE=n cargo test --release --test simulateur`).

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

type Connexion = Tcb<Octets>;

const MS: u64 = 1_000_000;
const S: u64 = 1_000 * MS;
const MSS: u16 = 1460;
/// L'échelle de fenêtre proposée des deux côtés.
const ECHELLE: u8 = 7;

/// Un générateur pseudo-aléatoire (xorshift64*), rejouable par sa graine.
struct Alea(u64);

impl Alea {
    fn new(graine: u64) -> Alea {
        Alea(graine.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// Un entier de 0 à n - 1.
    fn sous(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.suivant() % n }
    }
    /// Vrai avec la probabilité `p` pour mille.
    fn pour_mille(&mut self, p: u64) -> bool {
        self.sous(1000) < p
    }
}

/// L'octet `i` du flux qu'écrit le côté `cote` : une suite qu'on peut
/// recalculer, pour vérifier chaque octet lu.
fn octet(cote: u8, i: usize) -> u8 {
    ((i as u64).wrapping_mul(2_654_435_761) >> 13) as u8 ^ cote.wrapping_mul(0x5b) ^ (i >> 16) as u8
}

/// Un segment en route.
struct EnRoute {
    arrivee: u64,
    /// L'ordre d'envoi, pour départager deux arrivées à la même heure.
    ordre: u64,
    vers_b: bool,
    entete: Tcp,
    charge: Vec<u8>,
}

/// Le lien entre les deux côtés.
struct Lien {
    perte: u64,
    duplication: u64,
    delai: u64,
    gigue: u64,
}

/// Un côté : sa connexion, et son programme.
struct Cote {
    nom: u8,
    tcb: Option<Connexion>,
    /// Ce qu'il doit écrire, et ce qu'il a écrit.
    total: usize,
    ecrits: usize,
    ferme: bool,
    /// Ce qu'il a lu (et vérifié), et s'il a vu la fin de l'autre.
    lus: usize,
    fin_vue: bool,
    /// L'erreur qui a fermé sa connexion.
    erreur: i32,
    /// Sa prochaine action (None : il n'a rien à faire pour l'instant).
    prochaine: Option<u64>,
}

impl Cote {
    /// La connexion est au bout (fermée, ou en TIME_WAIT), et le programme
    /// a tout lu jusqu'au FIN de l'autre.
    fn fini(&self) -> bool {
        self.fin_vue && self.tcb.as_ref().is_some_and(|c| matches!(c.etat(), Etat::Fermee | Etat::TempsAttente))
    }
}

struct Simulation {
    graine: u64,
    alea: Alea,
    lien: Lien,
    heure: u64,
    ordre: u64,
    en_route: Vec<EnRoute>,
    a: Cote,
    b: Cote,
    /// Des statistiques, pour s'assurer que les essais exercent bien ce
    /// qu'ils doivent.
    segments: u64,
    perdus: u64,
    /// Les segments de données renvoyés (avant le plus loin déjà envoyé).
    renvois: u64,
    /// Le plus loin envoyé par A et par B.
    plus_loin: [Option<u32>; 2],
}

impl Simulation {
    fn nouvelle(graine: u64) -> Simulation {
        let mut alea = Alea::new(graine);
        // Le lien : le plus souvent des pertes modérées, parfois fortes.
        let perte = match alea.sous(4) {
            0 => 0,
            1 => alea.sous(20),
            2 => alea.sous(100),
            _ => alea.sous(300),
        };
        let delai = (1 + alea.sous(50)) * MS;
        let lien = Lien { perte, duplication: alea.sous(30), delai, gigue: alea.sous(delai + 1) };
        // Les gros transferts sur un lien à pertes modérées seulement : au
        // delà de 10 %, perdus dans un sens ou dans l'autre (ACK compris),
        // près d'un aller-retour sur deux échoue, et sans SACK ni
        // horodatages aucune retransmission ne mesure le RTT (Karn) : le
        // RTO recule jusqu'à la minute et le débit tombe à quelques
        // centaines d'octets par seconde, chez Linux aussi. Ces liens-là
        // servent à éprouver les retransmissions et les abandons.
        let max = if perte > 100 { 300_000 } else { 8 << 20 };
        let taille = |alea: &mut Alea| match alea.sous(5) {
            0 => 0,
            1 => alea.sous(10_000) as usize,
            2 => alea.sous(300_000.min(max)) as usize,
            3 => alea.sous((2 << 20).min(max)) as usize,
            _ => alea.sous(max) as usize,
        };
        let (ta, tb) = (taille(&mut alea), taille(&mut alea));
        let cote = |nom, total| Cote { nom, tcb: None, total, ecrits: 0, ferme: false, lus: 0, fin_vue: false, erreur: 0, prochaine: Some(0) };
        let mut a = cote(1, ta);
        let b = cote(2, tb);
        // Des numéros de séquence initiaux au hasard : ils font le tour
        // des 32 bits.
        let iss = alea.suivant() as u32;
        let mut c = Connexion::connecter(40_000, 80, iss, MSS, 131_072, 65_536, ECHELLE);
        // Un essai sur deux avec les horodatages ; sans, le cas de slirp.
        if alea.sous(2) == 0 {
            c.proposer_horodatages(alea.suivant() as u32);
        }
        // De même avec SACK, indépendamment.
        if alea.sous(2) == 0 {
            c.proposer_sack();
        }
        a.tcb = Some(c);
        Simulation { graine, alea, lien, heure: 0, ordre: 0, en_route: Vec::new(), a, b, segments: 0, perdus: 0, renvois: 0, plus_loin: [None; 2] }
    }

    /// Ce que dit un échec : de quoi rejouer l'essai.
    fn contexte(&self) -> String {
        format!(
            "graine {} : pertes {} ‰, duplications {} ‰, délai {} ms, gigue {} ms, {} et {} octets, heure {} ms, \
             A {:?} (lus {}, erreur {}), B {:?} (lus {}, erreur {})",
            self.graine, self.lien.perte, self.lien.duplication, self.lien.delai / MS, self.lien.gigue / MS,
            self.a.total, self.b.total, self.heure / MS,
            self.a.tcb.as_ref().map(|c| c.etat()), self.a.lus, self.a.erreur,
            self.b.tcb.as_ref().map(|c| c.etat()), self.b.lus, self.b.erreur,
        )
    }

    /// Ce que le côté `de_a` (ou B) envoie part sur le lien.
    fn emettre(&mut self, de_a: bool) {
        let heure = self.heure;
        let cote = if de_a { &mut self.a } else { &mut self.b };
        let Some(c) = cote.tcb.as_mut() else { return };
        let mut sortants: Vec<Sortant> = Vec::new();
        c.emettre(heure, |s| sortants.push(s));
        // Les comptes de la file (`tcp_verify_left_out`) : ils ne dépassent
        // jamais ce qui est en file. (Un compte retombé sous zéro y ferait un
        // très grand nombre.)
        let i = c.info(heure);
        assert!(i.sackes + i.perdus <= i.non_acquittes && i.retransmis <= i.non_acquittes && i.cwnd >= 1,
                "graine {} : en file {}, arrivés {}, perdus {}, renvoyés {}, cwnd {}", self.graine, i.non_acquittes, i.sackes, i.perdus, i.retransmis, i.cwnd);
        let segments: Vec<(Tcp, Vec<u8>)> = sortants
            .into_iter()
            .map(|s| {
                let mut o = vec![0u8; s.longueur];
                c.copier_envoi(s.debut, &mut o);
                (s.entete, o)
            })
            .collect();
        let trace = std::env::var("SIMULATEUR_TRACE").is_ok();
        for (h, o) in segments {
            if trace {
                let c = cote.tcb.as_ref().unwrap();
                eprintln!("{:>9} {} seq {} ack {} len {} fl {:02x} win {} | cc {:?} num {:?}", self.heure / MS, if de_a { "A>" } else { "<B" }, h.seq, h.ack, o.len(), h.drapeaux, h.fenetre, c.congestion(), c.numeros());
            }
            self.segments += 1;
            let fin = h.seq.wrapping_add(o.len() as u32);
            let loin = &mut self.plus_loin[usize::from(!de_a)];
            if !o.is_empty() {
                match *loin {
                    Some(l) if !t::apres(fin, l) => self.renvois += 1,
                    _ => *loin = Some(fin),
                }
            }
            if self.alea.pour_mille(self.lien.perte) {
                self.perdus += 1;
                continue;
            }
            let copies = if self.alea.pour_mille(self.lien.duplication) { 2 } else { 1 };
            for _ in 0..copies {
                let arrivee = self.heure + self.lien.delai + self.alea.sous(self.lien.gigue + 1);
                self.ordre += 1;
                self.en_route.push(EnRoute { arrivee, ordre: self.ordre, vers_b: de_a, entete: h, charge: o.clone() });
            }
        }
    }

    /// Le programme d'un côté agit : il lit, il écrit, il ferme.
    fn agir(&mut self, de_a: bool) {
        let heure = self.heure;
        let graine = self.graine;
        let alea = &mut self.alea;
        let cote = if de_a { &mut self.a } else { &mut self.b };
        cote.prochaine = None;
        let nom_autre = if de_a { 2 } else { 1 };
        let Some(c) = cote.tcb.as_mut() else { return };
        let mut fait = false;
        // Lire, et vérifier chaque octet (l'invariant (a)).
        if c.lisibles() > 0 {
            let n = 1 + alea.sous(131_072) as usize;
            let debut = cote.lus;
            let mut i = debut;
            c.lire::<()>(n, false, |m| {
                for (k, &x) in m.iter().enumerate() {
                    assert_eq!(x, octet(nom_autre, i + k), "graine {graine} : l'octet {} lu est faux", i + k);
                }
                i += m.len();
                Ok(m.len())
            })
            .unwrap();
            cote.lus = i;
            c.lu();
            fait = i > debut;
        }
        if c.fin_recue() && c.lisibles() == 0 && !cote.fin_vue {
            cote.fin_vue = true;
            fait = true;
        }
        // Écrire, puis fermer.
        if matches!(c.etat(), Etat::Etablie | Etat::AttenteFermeture) && cote.ecrits < cote.total && c.place() > 0 {
            let n = (1 + alea.sous(65_536) as usize).min(cote.total - cote.ecrits);
            let nom = cote.nom;
            // `ecrire` remplit ses blocs morceau par morceau : chaque appel
            // de `remplir` reprend où le précédent s'est arrêté.
            let mut position = cote.ecrits;
            let ecrit = c
                .ecrire::<()>(n, |o| {
                    for x in o.iter_mut() {
                        *x = octet(nom, position);
                        position += 1;
                    }
                    Ok(())
                })
                .unwrap();
            cote.ecrits += ecrit;
            fait |= ecrit > 0;
        }
        if cote.ecrits == cote.total && !cote.ferme && matches!(c.etat(), Etat::Etablie | Etat::AttenteFermeture) {
            c.fermer_envoi();
            cote.ferme = true;
            fait = true;
        }
        if fait {
            // Le plus souvent tout de suite, parfois une longue pause (la
            // fenêtre se ferme, l'autre sonde).
            let pause = if alea.pour_mille(5) { (1 + alea.sous(5)) * S } else { alea.sous(20 * MS) };
            cote.prochaine = Some(heure + pause);
        }
    }

    /// Réveille le programme d'un côté après un événement de sa connexion.
    fn reveiller(&mut self, de_a: bool) {
        let heure = self.heure;
        let pause = self.alea.sous(5 * MS);
        let cote = if de_a { &mut self.a } else { &mut self.b };
        if cote.prochaine.is_none() {
            cote.prochaine = Some(heure + pause);
        }
    }

    /// Le segment `s` arrive.
    fn arriver(&mut self, s: EnRoute) {
        let heure = self.heure;
        let cote = if s.vers_b { &mut self.b } else { &mut self.a };
        match cote.tcb.as_mut() {
            Some(c) => {
                c.recevoir(&s.entete, Octets(s.charge, 0), heure);
            }
            None => {
                // B n'existe qu'au premier SYN (la fille d'une écoute).
                if s.entete.drapeaux & (tcp::SYN | tcp::ACK) == tcp::SYN {
                    let iss = self.alea.suivant() as u32;
                    let mut c = Connexion::depuis_syn(&s.entete, iss, MSS, 131_072, 65_536, ECHELLE);
                    c.decalage_horodatages(iss);
                    cote.tcb = Some(c);
                }
            }
        }
        self.reveiller(!s.vers_b);
    }

    /// Fait tout l'essai.
    fn jouer(&mut self) {
        // Le budget de `tcp_retries2` deux fois, plus la taille du transfert
        // à 1 Kio/s ; au-delà de 10 % de pertes, le même budget pour chaque
        // progrès.
        let budget = 2 * t::temps_modele(t::RETRIES2, t::RTO_MIN);
        let echeance = budget + (self.a.total + self.b.total) as u64 * S / 1024 + 300 * S;
        let mut progres = (0, 0);
        let mut dernier_progres = 0;
        loop {
            self.emettre(true);
            self.emettre(false);
            for de_a in [true, false] {
                let cote = if de_a { &mut self.a } else { &mut self.b };
                if let Some(c) = cote.tcb.as_mut()
                    && c.etat() == Etat::Fermee
                    && cote.erreur == 0
                {
                    cote.erreur = c.prendre_erreur();
                }
            }
            // Fini : les deux côtés au bout (fermés ou en TIME_WAIT), ou une
            // erreur d'un côté (l'autre peut rester ouvert pour toujours :
            // il ne peut pas le savoir, sans keepalive).
            if (self.a.fini() && self.b.fini() && self.en_route.is_empty()) || self.a.erreur != 0 || self.b.erreur != 0 {
                return;
            }
            let mut prochaine: Option<u64> = None;
            let mut garder = |e: Option<u64>| {
                if let Some(e) = e {
                    prochaine = Some(prochaine.map_or(e, |p| p.min(e)));
                }
            };
            garder(self.en_route.iter().map(|s| s.arrivee).min());
            garder(self.a.tcb.as_ref().and_then(|c| c.echeance()));
            garder(self.b.tcb.as_ref().and_then(|c| c.echeance()));
            garder(self.a.prochaine);
            garder(self.b.prochaine);
            let Some(p) = prochaine else {
                // Plus rien ne peut arriver.
                return;
            };
            let etat = |c: &Cote| c.tcb.as_ref().map(|c| c.etat());
            let maintenant = (self.a.lus + self.b.lus + self.a.ecrits + self.b.ecrits, etat(&self.a).map(Etat::linux).unwrap_or(0) as usize * 16 + etat(&self.b).map(Etat::linux).unwrap_or(0) as usize);
            if maintenant != progres {
                progres = maintenant;
                dernier_progres = self.heure;
            }
            if self.lien.perte <= 100 {
                assert!(p <= echeance, "l'essai ne finit pas : {}", self.contexte());
            } else {
                assert!(p <= dernier_progres + budget, "plus rien n'avance : {}", self.contexte());
            }
            self.heure = self.heure.max(p);
            // Les arrivées, dans l'ordre.
            loop {
                let suivante = self
                    .en_route
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.arrivee <= self.heure)
                    .min_by_key(|(_, s)| (s.arrivee, s.ordre))
                    .map(|(i, _)| i);
                let Some(i) = suivante else { break };
                let s = self.en_route.swap_remove(i);
                self.arriver(s);
            }
            // Les minuteurs.
            for de_a in [true, false] {
                let heure = self.heure;
                let cote = if de_a { &mut self.a } else { &mut self.b };
                if let Some(c) = cote.tcb.as_mut()
                    && c.echeance().is_some_and(|e| e <= heure)
                {
                    c.minuteur(heure);
                    self.reveiller(de_a);
                }
            }
            // Les programmes.
            for de_a in [true, false] {
                let cote = if de_a { &self.a } else { &self.b };
                if cote.prochaine.is_some_and(|p| p <= self.heure) {
                    self.agir(de_a);
                }
            }
        }
    }

    /// Les invariants de la fin (b) et (c).
    fn verifier(&self) {
        let ctx = self.contexte();
        for (cote, autre) in [(&self.a, &self.b), (&self.b, &self.a)] {
            // Un FIN vu : tout ce que l'autre a écrit a été lu.
            if cote.fin_vue {
                assert_eq!(cote.lus, autre.total, "un FIN avant la fin des données : {ctx}");
            }
            assert!(
                [0, t::ETIMEDOUT, t::ECONNRESET, t::EPIPE].contains(&cote.erreur),
                "une erreur inattendue : {ctx}"
            );
        }
        let erreur = self.a.erreur != 0 || self.b.erreur != 0;
        if !erreur {
            // La fin propre : tout lu, les deux FIN, au moins un TIME_WAIT.
            for (cote, autre) in [(&self.a, &self.b), (&self.b, &self.a)] {
                assert!(cote.fin_vue && cote.lus == autre.total, "une fin sans erreur mais incomplète : {ctx}");
            }
            let etats = [self.a.tcb.as_ref().map(|c| c.etat()), self.b.tcb.as_ref().map(|c| c.etat())];
            assert!(etats.contains(&Some(Etat::TempsAttente)), "personne en TIME_WAIT : {ctx}");
        }
        if self.lien.perte <= 100 {
            assert!(!erreur, "une erreur à {} ‰ de pertes : {ctx}", self.lien.perte);
        }
    }
}

#[test]
fn simulateur() {
    let graines: Vec<u64> = match std::env::var("SIMULATEUR_GRAINE") {
        Ok(g) => vec![g.parse().expect("une graine")],
        Err(_) => (1..=std::env::var("SIMULATEUR_ESSAIS").map_or(200, |n| n.parse().expect("un nombre"))).collect(),
    };
    let (mut pertes, mut segments, mut erreurs, mut octets, mut renvois) = (0, 0, 0, 0, 0);
    for g in graines {
        let mut s = Simulation::nouvelle(g);
        s.jouer();
        s.verifier();
        pertes += s.perdus;
        renvois += s.renvois;
        segments += s.segments;
        octets += s.a.lus + s.b.lus;
        erreurs += u64::from(s.a.erreur != 0 || s.b.erreur != 0);
    }
    eprintln!("[simulateur] {segments} segments, {pertes} perdus, {renvois} renvoyés, {octets} octets livrés, {erreurs} abandons");
}
