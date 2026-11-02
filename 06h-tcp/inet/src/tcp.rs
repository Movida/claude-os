//! Une connexion TCP (RFC 9293), sans le matériel : la machine à états et
//! ses variables (le `tcp_sock` de Linux, net/ipv4/tcp*.c), testée sur
//! l'hôte. Le noyau (noyau/src/reseau/tcp.rs) garde les sockets, leurs
//! verrous, les tables, les échéances, les attentes des programmes et les
//! copies ; ici, les RÈGLES : ce que fait chaque segment reçu dans chaque
//! état, ce qu'il faut envoyer, ce que voit le programme.
//!
//! TCP en deux mots. Chaque octet envoyé a un numéro de séquence (sur 32
//! bits, qui reviennent à zéro : toutes les comparaisons se font modulo
//! 2³², `avant`). Chaque côté choisit son premier numéro (l'ISN, tiré par
//! le noyau : RFC 6528) et l'annonce dans son SYN ; l'autre l'acquitte
//! (ACK = le prochain octet attendu). La poignée de main : SYN, SYN-ACK,
//! ACK. Chacun dit aussi combien il peut encore recevoir (la FENÊTRE) :
//! l'émetteur n'envoie jamais au-delà. La fin : chaque sens se ferme par un
//! FIN (qui compte pour un octet), acquitté ; le côté qui ferme le premier
//! attend ensuite deux fois la durée de vie d'un segment (TIME_WAIT, 60 s
//! chez Linux), pour qu'un vieux segment de la connexion ne soit pas pris
//! pour un segment d'une suivante. RST coupe tout, tout de suite.
//!
//! LES ÉTATS (RFC 9293, 3.3.2) : SYN_SENT (un `connect`), SYN_RECEIVED (un
//! SYN reçu par une écoute ; la fille d'une écoute, plan de 6h), ESTABLISHED,
//! puis la fermeture : FIN_WAIT_1 et FIN_WAIT_2 (nous avons fermé),
//! CLOSE_WAIT (l'autre a fermé), CLOSING (les deux à la fois), LAST_ACK
//! (l'autre avait fermé, puis nous), TIME_WAIT, et CLOSED. L'écoute
//! (LISTEN) n'est pas une connexion : c'est le noyau qui la tient, et qui
//! crée une `Tcb` par SYN reçu.
//!
//! CE QUE FAIT CETTE SOUS-ÉTAPE (6h, commit 5) : la poignée de main, les
//! données dans l'ordre, la fenêtre (sans échelle), l'ACK après lecture
//! (`lu`, le `tcp_cleanup_rbuf` de Linux), les fermetures dans tous leurs
//! états, RST, les erreurs ICMP ; un segment hors d'ordre est jeté
//! (et l'ACK redit ce qu'on attend). La retransmission, la congestion, la
//! file hors d'ordre, les ACK retardés, Nagle, l'échelle de fenêtre, les
//! sondes et le keepalive viennent au commit suivant : sans eux, une
//! connexion ne survit pas à une perte, ce qui n'arrive ni sur `lo` ni avec
//! slirp.
//!
//! LES TAMPONS : les données à envoyer, des blocs de 64 Kio au plus (la
//! `size_goal` de Linux), remplis par `ecrire`, découpés au MSS par
//! `emettre`, rendus quand ils sont acquittés ; les données reçues, les
//! charges des segments telles quelles (`P`, le paquet du noyau : aucune
//! copie de plus), lues par `lire`. Tout est alloué faillible : un manque
//! de mémoire jette le segment reçu (il reviendra), ou rend moins à
//! `ecrire`, jamais une panique.
//!
//! L'heure et le hasard sont des arguments (l'ISN est tiré par le noyau) ;
//! les segments à envoyer sont rendus par `emettre` ; les copies vers et
//! depuis le programme passent par des fonctions données.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use formats::reseau::tcp::{self, Tcp};

/// La plus grande taille d'un bloc du tampon d'émission.
pub const BLOC: usize = 65_536;
/// Le MSS par défaut, quand l'autre n'en dit rien (RFC 9293 : 536).
pub const MSS_DEFAUT: u16 = 536;
/// Le plus petit MSS (TCP_MIN_MSS de Linux, que TCP_MAXSEG ne peut pas
/// descendre plus bas).
pub const MSS_MIN: u16 = 88;
/// Le plus petit MSS d'envoi, quoi que propose l'autre (`tcp_min_snd_mss`,
/// la correction de CVE-2019-11479 : sans plancher, un pair qui annonce un
/// MSS de 1 fait découper tout ce qu'on envoie en segments d'un octet).
pub const MSS_ENVOI_MIN: u16 = 48;
/// La plus grande fenêtre sans échelle.
pub const FENETRE_MAX: u32 = 65_535;

// Les errno que voit le programme.
pub const ECONNREFUSED: i32 = 111;
pub const ECONNRESET: i32 = 104;
pub const EPIPE: i32 = 32;
pub const ETIMEDOUT: i32 = 110;

/// `a` est-il avant `b`, modulo 2³² (le `before` de Linux) ?
pub fn avant(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// `a` est-il après `b` ?
pub fn apres(a: u32, b: u32) -> bool {
    avant(b, a)
}

/// Les états d'une connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etat {
    SynEnvoye,
    SynRecu,
    Etablie,
    FinAttente1,
    FinAttente2,
    AttenteFermeture,
    Fermeture,
    DernierAck,
    TempsAttente,
    Fermee,
}

impl Etat {
    /// Le numéro de l'état chez Linux (`TCP_ESTABLISHED`... : /proc/net/tcp,
    /// TCP_INFO).
    pub fn linux(self) -> u8 {
        match self {
            Etat::Etablie => 1,
            Etat::SynEnvoye => 2,
            Etat::SynRecu => 3,
            Etat::FinAttente1 => 4,
            Etat::FinAttente2 => 5,
            Etat::TempsAttente => 6,
            Etat::Fermee => 7,
            Etat::AttenteFermeture => 8,
            Etat::DernierAck => 9,
            Etat::Fermeture => 11,
        }
    }

    /// La connexion est-elle « synchronisée » (après la poignée de main) ?
    fn synchronise(self) -> bool {
        !matches!(self, Etat::SynEnvoye | Etat::SynRecu | Etat::Fermee)
    }
}

/// Une charge reçue, gardée telle quelle dans la file de réception : le
/// paquet du noyau, réduit à sa charge TCP.
pub trait Charge {
    /// Les octets (ce qui reste à lire).
    fn octets(&self) -> &[u8];
    /// Retire `n` octets du début (lus, ou déjà reçus).
    fn avancer(&mut self, n: usize);
    /// Ce qu'elle occupe en mémoire (la taille vraie, que compte
    /// SO_RCVBUF).
    fn taille_vraie(&self) -> usize;
}

/// Un segment à envoyer : son en-tête, et sa charge, désignée dans le
/// tampon d'émission (le noyau la copie par `copier_envoi`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sortant {
    pub entete: Tcp,
    /// Le décalage de la charge depuis le début du tampon d'émission, et sa
    /// longueur.
    pub debut: usize,
    pub longueur: usize,
}

/// Ce qu'un événement a changé, pour réveiller qui attend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Effets {
    /// Des octets (ou la fin de l'autre sens, ou une erreur) à lire.
    pub lisible: bool,
    /// De la place s'est libérée dans le tampon d'émission.
    pub place: bool,
    /// L'état a changé (établie, fermée...).
    pub etat: bool,
    /// Il y a quelque chose à envoyer (`emettre`).
    pub a_emettre: bool,
}

impl Effets {
    pub fn ou(&mut self, autre: Effets) {
        self.lisible |= autre.lisible;
        self.place |= autre.place;
        self.etat |= autre.etat;
        self.a_emettre |= autre.a_emettre;
    }
}

/// Une connexion.
pub struct Tcb<P: Charge> {
    etat: Etat,
    /// Les ports et adresses : du noyau, recopiés dans chaque en-tête.
    pub port_local: u16,
    pub port_distant: u16,
    // L'émission (RFC 9293, 3.3.1).
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    // La réception.
    irs: u32,
    rcv_nxt: u32,
    /// Le bord droit de la fenêtre annoncée (rcv_nxt + fenêtre), qui ne
    /// recule jamais (RFC 9293, 3.8.6.2.2).
    rcv_bord: u32,
    /// Une fenêtre a déjà été annoncée (le bord droit a un sens).
    bord_pose: bool,
    /// Le MSS qu'on envoie : celui de l'autre, borné par le nôtre.
    mss: u16,
    /// Le MSS qu'on annonce (la MTU de notre chemin moins 40).
    mss_local: u16,
    /// TCP_MAXSEG demandé (0 : rien).
    pub mss_utilisateur: u16,
    // Le tampon d'émission : les octets de snd_una (sans le SYN) en
    // avant, par blocs ; le premier bloc commence à `decalage_envoi`.
    envoi: VecDeque<Vec<u8>>,
    decalage_envoi: usize,
    octets_envoi: usize,
    /// Le programme ne veut plus écrire : FIN à envoyer après les données.
    fin_voulue: bool,
    /// Le FIN est parti (son numéro : snd_nxt - 1 une fois envoyé).
    fin_envoye: bool,
    // La réception.
    reception: VecDeque<P>,
    octets_reception: usize,
    taille_vraie_reception: usize,
    /// L'autre a fermé son sens (FIN reçu et accepté).
    fin_recue: bool,
    /// Les tailles des tampons (SO_RCVBUF, SO_SNDBUF, déjà doublées).
    pub rcvbuf: usize,
    pub sndbuf: usize,
    /// L'erreur à rendre au programme (`sk_err`), et l'erreur « douce »
    /// d'un ICMP (`sk_err_soft`).
    erreur: i32,
    erreur_douce: i32,
    /// Plus personne ne lira (le `RCV_SHUTDOWN` de Linux : `close`, ou
    /// shutdown(SHUT_RD)) : en FIN_WAIT, des données neuves coupent la
    /// connexion (RFC 1122, 4.2.2.13).
    lecture_fermee: bool,
    /// Un ACK (ou un RST, un SYN-ACK) attend d'être envoyé.
    ack_du: bool,
    syn_du: bool,
    rst_du: Option<(u32, u32, u8)>,
}

impl<P: Charge> Tcb<P> {
    fn vide(port_local: u16, port_distant: u16, iss: u32, mss_local: u16, rcvbuf: usize, sndbuf: usize) -> Tcb<P> {
        Tcb {
            etat: Etat::Fermee,
            port_local,
            port_distant,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_bord: 0,
            bord_pose: false,
            mss: MSS_DEFAUT,
            mss_local,
            mss_utilisateur: 0,
            envoi: VecDeque::new(),
            decalage_envoi: 0,
            octets_envoi: 0,
            fin_voulue: false,
            fin_envoye: false,
            reception: VecDeque::new(),
            octets_reception: 0,
            taille_vraie_reception: 0,
            fin_recue: false,
            rcvbuf,
            sndbuf,
            erreur: 0,
            erreur_douce: 0,
            lecture_fermee: false,
            ack_du: false,
            syn_du: false,
            rst_du: None,
        }
    }

    /// Une connexion qui s'ouvre (`connect`) : SYN_SENT, le SYN à envoyer.
    pub fn connecter(port_local: u16, port_distant: u16, iss: u32, mss_local: u16, rcvbuf: usize, sndbuf: usize) -> Tcb<P> {
        let mut t = Tcb::vide(port_local, port_distant, iss, mss_local, rcvbuf, sndbuf);
        t.etat = Etat::SynEnvoye;
        t.syn_du = true;
        t
    }

    /// La fille d'une écoute, pour le SYN `syn` reçu : SYN_RECEIVED, le
    /// SYN-ACK à envoyer.
    pub fn depuis_syn(syn: &Tcp, iss: u32, mss_local: u16, rcvbuf: usize, sndbuf: usize) -> Tcb<P> {
        let mut t = Tcb::vide(syn.destination, syn.source, iss, mss_local, rcvbuf, sndbuf);
        t.etat = Etat::SynRecu;
        t.irs = syn.seq;
        t.rcv_nxt = syn.seq.wrapping_add(1);
        t.snd_wnd = syn.fenetre as u32;
        t.snd_wl1 = syn.seq;
        t.mss = t.mss_effectif(syn.options.mss);
        t.annoncer();
        t.syn_du = true;
        t
    }

    pub fn etat(&self) -> Etat {
        self.etat
    }

    /// SND.UNA, SND.NXT et RCV.NXT (/proc/net/tcp, TCP_INFO, les tests).
    pub fn numeros(&self) -> (u32, u32, u32) {
        (self.snd_una, self.snd_nxt, self.rcv_nxt)
    }

    /// Le MSS d'envoi pour ce que l'autre propose : son offre (536 s'il ne
    /// dit rien, ou dit 0 : `tcp_parse_options` l'ignore), bornée par le
    /// nôtre et par TCP_MAXSEG, et jamais sous MSS_ENVOI_MIN
    /// (`__tcp_mtu_to_mss`).
    fn mss_effectif(&self, offre: Option<u16>) -> u16 {
        let mut m = offre.filter(|&o| o != 0).unwrap_or(MSS_DEFAUT).min(self.mss_local);
        if self.mss_utilisateur != 0 {
            m = m.min(self.mss_utilisateur);
        }
        m.max(MSS_ENVOI_MIN)
    }

    /// Ce que rend TCP_MAXSEG : le MSS d'envoi une fois la connexion
    /// établie ; avant, ce qu'a demandé le programme, ou 536 (mesuré).
    pub fn mss(&self) -> u16 {
        if self.etat.synchronise() {
            self.mss
        } else if self.mss_utilisateur != 0 {
            self.mss_utilisateur
        } else {
            MSS_DEFAUT
        }
    }

    // --- La réception, vue du programme ---

    /// Les octets à lire.
    pub fn lisibles(&self) -> usize {
        self.octets_reception
    }

    /// Plus personne ne lira (`close` d'une orpheline, shutdown(SHUT_RD)).
    pub fn fermer_lecture(&mut self) {
        self.lecture_fermee = true;
    }

    /// L'autre a-t-il fermé son sens (une lecture rendra 0 après les
    /// données) ?
    pub fn fin_recue(&self) -> bool {
        self.fin_recue
    }

    /// L'erreur en attente (0 : aucune), sans l'effacer.
    pub fn erreur(&self) -> i32 {
        self.erreur
    }

    /// Prend l'erreur en attente (SO_ERROR, ou ce que rend un appel).
    pub fn prendre_erreur(&mut self) -> i32 {
        core::mem::take(&mut self.erreur)
    }

    /// L'erreur douce (d'un ICMP), que rendra un abandon.
    pub fn erreur_douce(&self) -> i32 {
        self.erreur_douce
    }

    /// Copie jusqu'à `n` octets reçus par `copier` (qui rend combien elle a
    /// copié d'un morceau, ou une erreur) ; `garder` : MSG_PEEK, rien n'est
    /// retiré. Rend le nombre d'octets copiés (moins si `copier` en prend
    /// moins). L'appelant appelle ensuite `lu` (la fenêtre).
    pub fn lire<E>(&mut self, n: usize, garder: bool, mut copier: impl FnMut(&[u8]) -> Result<usize, E>) -> Result<usize, E> {
        let mut fait = 0;
        let mut i = 0;
        while fait < n && i < self.reception.len() {
            let morceau = self.reception[i].octets();
            let m = morceau.len().min(n - fait);
            // Une copie qui échoue après des octets déjà pris rend ce qui a
            // été lu ; l'erreur, seulement si rien ne l'a été
            // (`tcp_recvmsg_locked`) : sans cela, ces octets seraient perdus.
            let c = match copier(&morceau[..m]) {
                Ok(c) => c,
                Err(_) if fait > 0 => break,
                Err(e) => return Err(e),
            };
            fait += c;
            if garder {
                if c < m {
                    break;
                }
                i += 1;
                continue;
            }
            let p = &mut self.reception[i];
            p.avancer(c);
            self.octets_reception -= c;
            if p.octets().is_empty() {
                let p = self.reception.pop_front().expect("le premier paquet");
                self.taille_vraie_reception = self.taille_vraie_reception.saturating_sub(p.taille_vraie());
            } else if c < m {
                break;
            }
        }
        Ok(fait)
    }

    /// Jette jusqu'à `n` octets reçus (MSG_TRUNC de TCP) ; rend combien.
    pub fn jeter(&mut self, n: usize) -> usize {
        self.lire::<()>(n, false, |m| Ok(m.len())).unwrap_or(0)
    }

    /// La place libre de la réception, en taille vraie.
    fn libre(&self) -> usize {
        self.rcvbuf.saturating_sub(self.taille_vraie_reception)
    }

    /// La fenêtre que permet la place libre : la moitié (le `scaling_ratio`
    /// de Linux à sa valeur de départ, 50 % : une charge reçue occupe à peu
    /// près le double de ses octets en mémoire), sans échelle au plus
    /// 65 535 ; moins d'un MSS : 0 (le récepteur n'annonce pas de petite
    /// fenêtre, RFC 9293 3.8.6.2.2, le SWS).
    fn fenetre_possible(&self) -> u32 {
        let f = ((self.libre() / 2) as u32).min(FENETRE_MAX);
        if f < self.mss_local as u32 && f < (self.rcvbuf / 4) as u32 { 0 } else { f }
    }

    /// Pose le bord droit annoncé, sans jamais le reculer.
    fn annoncer(&mut self) {
        let bord = self.rcv_nxt.wrapping_add(self.fenetre_possible());
        if !self.bord_pose || apres(bord, self.rcv_bord) {
            self.rcv_bord = bord;
            self.bord_pose = true;
        }
        if avant(self.rcv_bord, self.rcv_nxt) {
            self.rcv_bord = self.rcv_nxt;
        }
    }

    /// La fenêtre à annoncer dans un segment.
    fn fenetre(&self) -> u16 {
        self.rcv_bord.wrapping_sub(self.rcv_nxt).min(FENETRE_MAX) as u16
    }

    /// Le programme a lu (`tcp_cleanup_rbuf`) : si la fenêtre qu'on pourrait
    /// annoncer a au moins doublé depuis la dernière annonce, un ACK la dit
    /// tout de suite (sans lui, un émetteur bloqué par une fenêtre nulle
    /// attendrait une sonde).
    pub fn lu(&mut self) -> Effets {
        if !self.etat.synchronise() && self.etat != Etat::SynRecu {
            return Effets::default();
        }
        let annoncee = self.rcv_bord.wrapping_sub(self.rcv_nxt);
        let possible = self.fenetre_possible();
        let mut e = Effets::default();
        if possible > 0 && possible >= 2 * annoncee.max(1) && !self.fin_recue {
            self.annoncer();
            self.ack_du = true;
            e.a_emettre = true;
        }
        e
    }

    // --- L'émission, vue du programme ---

    /// La place libre du tampon d'émission, en octets.
    pub fn place(&self) -> usize {
        self.sndbuf.saturating_sub(self.octets_envoi)
    }

    /// Les octets pas encore acquittés (SIOCOUTQ), et pas encore envoyés
    /// (SIOCOUTQNSD).
    pub fn non_acquittes(&self) -> usize {
        self.octets_envoi
    }

    pub fn non_envoyes(&self) -> usize {
        self.octets_envoi.saturating_sub(self.envoyes())
    }

    /// Les octets du tampon déjà envoyés (de snd_una à snd_nxt, sans le SYN
    /// ni le FIN, qui comptent chacun pour un numéro mais pas dans le
    /// tampon).
    fn envoyes(&self) -> usize {
        let mut n = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        if self.snd_una == self.iss && self.snd_nxt != self.iss {
            n -= 1;
        }
        if self.fin_envoye && n > 0 {
            n -= 1;
        }
        n
    }

    /// Ajoute jusqu'à `n` octets au tampon d'émission, remplis par
    /// `remplir` (qui copie depuis le programme), dans la limite de la
    /// place ; rend combien. Moins si la mémoire manque (0 : rien n'a pu
    /// être ajouté). Le programme ne doit plus écrire après `fermer_envoi`.
    pub fn ecrire<E>(&mut self, n: usize, mut remplir: impl FnMut(&mut [u8]) -> Result<(), E>) -> Result<usize, E> {
        let n = n.min(self.place());
        let mut fait = 0;
        while fait < n {
            let dernier_plein = self.envoi.back().is_none_or(|b| b.len() >= BLOC);
            if dernier_plein {
                let mut b = Vec::new();
                if b.try_reserve_exact((n - fait).min(BLOC)).is_err() {
                    break;
                }
                if self.envoi.try_reserve(1).is_err() {
                    break;
                }
                self.envoi.push_back(b);
            }
            let b = self.envoi.back_mut().expect("un bloc");
            let m = (BLOC - b.len()).min(n - fait);
            if b.try_reserve(m).is_err() {
                break;
            }
            let debut = b.len();
            b.resize(debut + m, 0);
            if let Err(e) = remplir(&mut b[debut..]) {
                b.truncate(debut);
                if b.is_empty() {
                    self.envoi.pop_back();
                }
                return if fait == 0 { Err(e) } else { Ok(fait) };
            }
            fait += m;
            self.octets_envoi += m;
        }
        Ok(fait)
    }

    /// Copie dans `o` les octets du tampon d'émission à partir du décalage
    /// `debut` (celui d'un `Sortant`).
    pub fn copier_envoi(&self, mut debut: usize, o: &mut [u8]) {
        debut += self.decalage_envoi;
        let mut fait = 0;
        for b in &self.envoi {
            if debut >= b.len() {
                debut -= b.len();
                continue;
            }
            let m = (b.len() - debut).min(o.len() - fait);
            o[fait..fait + m].copy_from_slice(&b[debut..debut + m]);
            fait += m;
            debut = 0;
            if fait == o.len() {
                break;
            }
        }
    }

    /// Retire `n` octets acquittés du début du tampon d'émission.
    fn acquitter_octets(&mut self, mut n: usize) {
        n = n.min(self.octets_envoi);
        self.octets_envoi -= n;
        while n > 0 {
            let Some(b) = self.envoi.front() else { break };
            let reste = b.len() - self.decalage_envoi;
            if n >= reste {
                n -= reste;
                self.envoi.pop_front();
                self.decalage_envoi = 0;
            } else {
                self.decalage_envoi += n;
                n = 0;
            }
        }
    }

    /// Le programme ne veut plus écrire (`shutdown(SHUT_WR)`, ou `close`) :
    /// un FIN partira après les données (`tcp_shutdown`, `tcp_close_state`).
    pub fn fermer_envoi(&mut self) -> Effets {
        let mut e = Effets::default();
        match self.etat {
            Etat::Etablie | Etat::SynRecu => self.passer(Etat::FinAttente1, &mut e),
            Etat::AttenteFermeture => self.passer(Etat::DernierAck, &mut e),
            Etat::SynEnvoye => {
                // Rien n'est parti que le SYN : la connexion se ferme
                // (`tcp_close` : CLOSE depuis SYN_SENT).
                self.passer(Etat::Fermee, &mut e);
                return e;
            }
            _ => return e,
        }
        self.fin_voulue = true;
        e.a_emettre = true;
        e
    }

    /// Coupe la connexion (SO_LINGER 0, `close` avec des données non lues,
    /// `connect(AF_UNSPEC)`) : un RST, si la connexion était synchronisée,
    /// puis fermée (`tcp_disconnect`, `tcp_send_active_reset`).
    pub fn avorter(&mut self) -> Effets {
        let mut e = Effets::default();
        if matches!(self.etat, Etat::Etablie | Etat::AttenteFermeture | Etat::FinAttente1 | Etat::FinAttente2 | Etat::SynRecu) {
            self.rst_du = Some((self.snd_nxt, self.rcv_nxt, tcp::RST | tcp::ACK));
            e.a_emettre = true;
        }
        self.passer(Etat::Fermee, &mut e);
        e
    }

    fn passer(&mut self, etat: Etat, e: &mut Effets) {
        if self.etat != etat {
            self.etat = etat;
            e.etat = true;
            e.lisible = true;
            e.place = true;
        }
    }

    /// Une erreur qui ferme la connexion (`tcp_done_with_error`).
    fn finir(&mut self, erreur: i32, e: &mut Effets) {
        self.erreur = erreur;
        self.passer(Etat::Fermee, e);
        e.lisible = true;
        e.place = true;
    }

    // --- Les segments reçus ---

    /// La fenêtre de réception annoncée (`tw_rcv_wnd` d'une entrée de
    /// TIME_WAIT).
    pub fn fenetre_annoncee(&self) -> u32 {
        self.rcv_wnd()
    }

    /// La fenêtre de réception, pour l'acceptabilité.
    fn rcv_wnd(&self) -> u32 {
        self.rcv_bord.wrapping_sub(self.rcv_nxt)
    }

    /// Un segment est-il acceptable (RFC 9293, 3.10.7.4, le tableau des
    /// quatre cas) ?
    fn acceptable(&self, seq: u32, longueur: u32) -> bool {
        let wnd = self.rcv_wnd();
        let dans = |s: u32| !avant(s, self.rcv_nxt) && avant(s, self.rcv_nxt.wrapping_add(wnd));
        match (longueur, wnd) {
            (0, 0) => seq == self.rcv_nxt,
            (0, _) => dans(seq),
            (_, 0) => false,
            _ => dans(seq) || dans(seq.wrapping_add(longueur - 1)),
        }
    }

    /// Reçoit le segment `t`, de charge `charge` (vide pour un segment sans
    /// données), dans l'ordre de la RFC 9293 (3.10.7) et de
    /// `tcp_rcv_state_process`.
    pub fn recevoir(&mut self, t: &Tcp, mut charge: P) -> Effets {
        let mut e = Effets::default();
        let longueur_charge = charge.octets().len() as u32;
        let syn = t.drapeaux & tcp::SYN != 0;
        let fin = t.drapeaux & tcp::FIN != 0;
        let rst = t.drapeaux & tcp::RST != 0;
        let ack = t.drapeaux & tcp::ACK != 0;
        match self.etat {
            Etat::Fermee => {
                // Une connexion fermée n'a plus de table : le noyau répond
                // lui-même (RST).
                return e;
            }
            Etat::SynEnvoye => {
                // 3.10.7.3 : d'abord l'ACK.
                if ack && (!apres(t.ack, self.iss) || apres(t.ack, self.snd_nxt)) {
                    if !rst {
                        self.rst_du = Some((t.ack, 0, tcp::RST));
                        e.a_emettre = true;
                    }
                    return e;
                }
                if rst {
                    // Un RST qui acquitte notre SYN : refusé.
                    if ack {
                        self.finir(ECONNREFUSED, &mut e);
                    }
                    return e;
                }
                if !syn {
                    return e;
                }
                self.irs = t.seq;
                self.rcv_nxt = t.seq.wrapping_add(1);
                self.mss = self.mss_effectif(t.options.mss);
                self.bord_pose = false;
                self.annoncer();
                if ack {
                    self.snd_una = t.ack;
                    self.snd_wnd = t.fenetre as u32;
                    self.snd_wl1 = t.seq;
                    self.snd_wl2 = t.ack;
                    self.passer(Etat::Etablie, &mut e);
                    self.ack_du = true;
                    e.a_emettre = true;
                    e.place = true;
                } else {
                    // L'ouverture simultanée : SYN_RECEIVED, et notre SYN
                    // repart avec un ACK.
                    self.passer(Etat::SynRecu, &mut e);
                    self.syn_du = true;
                    e.a_emettre = true;
                }
                // Des données dans le SYN-ACK : Linux les garde ; ici
                // (rare), elles seront redemandées par l'ACK.
                return e;
            }
            _ => {}
        }
        // TIME_WAIT : un FIN retransmis est réacquitté ; un RST l'efface
        // (`tcp_timewait_state_process`, rfc1337 à 0).
        // L'ouverture simultanée : en SYN_RECEIVED, le SYN-ACK de l'autre,
        // qui acquitte notre SYN, vaut un ACK (son SYN déjà reçu est
        // ignoré : le `goto pass` de `tcp_validate_incoming`).
        let mut syn = syn;
        let mut seq = t.seq;
        if self.etat == Etat::SynRecu && syn && ack && t.seq.wrapping_add(1) == self.rcv_nxt && t.ack == self.snd_nxt {
            syn = false;
            seq = self.rcv_nxt;
        }
        // 1. Le numéro de séquence.
        let longueur = longueur_charge + u32::from(syn) + u32::from(fin);
        if !self.acceptable(seq, longueur) {
            if !rst {
                self.ack_du = true;
                e.a_emettre = true;
            }
            return e;
        }
        // 2. RST (RFC 5961 : exactement au bord gauche ; sinon, dans la
        // fenêtre, un ACK « de défi »).
        if rst {
            if t.seq != self.rcv_nxt {
                self.ack_du = true;
                e.a_emettre = true;
                return e;
            }
            let erreur = match self.etat {
                Etat::SynRecu | Etat::Fermeture | Etat::DernierAck | Etat::TempsAttente => 0,
                Etat::AttenteFermeture => EPIPE,
                _ => ECONNRESET,
            };
            if self.etat == Etat::SynRecu {
                // La fille d'une écoute : elle disparaît, sans erreur
                // (l'écoute ne l'avait pas encore donnée).
                self.passer(Etat::Fermee, &mut e);
            } else {
                self.finir(erreur, &mut e);
                if erreur == 0 {
                    self.erreur = 0;
                }
            }
            return e;
        }
        // 4. SYN dans une connexion synchronisée : un ACK de défi (RFC 5961,
        // 4.2) ; en SYN_RECEIVED, un SYN retransmis : notre SYN-ACK repart.
        if syn {
            if self.etat == Etat::SynRecu && t.seq.wrapping_add(1) == self.rcv_nxt {
                self.syn_du = true;
            } else {
                self.ack_du = true;
            }
            e.a_emettre = true;
            return e;
        }
        // 5. ACK.
        if !ack {
            return e;
        }
        if self.etat == Etat::SynRecu {
            if apres(t.ack, self.snd_una) && !apres(t.ack, self.snd_nxt) {
                self.passer(Etat::Etablie, &mut e);
                // Un SYN-ACK qui n'était pas encore parti (l'ouverture
                // simultanée) : notre SYN est acquitté, un ACK suffit.
                if core::mem::take(&mut self.syn_du) {
                    self.ack_du = true;
                    e.a_emettre = true;
                }
                self.snd_wnd = t.fenetre as u32;
                self.snd_wl1 = t.seq;
                self.snd_wl2 = t.ack;
            } else {
                self.rst_du = Some((t.ack, 0, tcp::RST));
                e.a_emettre = true;
                return e;
            }
        }
        if apres(t.ack, self.snd_nxt) {
            // Il acquitte ce qui n'a jamais été envoyé : ACK, et rien
            // d'autre (RFC 9293).
            self.ack_du = true;
            e.a_emettre = true;
            return e;
        }
        if apres(t.ack, self.snd_una) {
            let mut n = t.ack.wrapping_sub(self.snd_una) as usize;
            // Le SYN compte pour un, pas dans le tampon.
            if self.snd_una == self.iss {
                n -= 1;
            }
            // Le FIN aussi, à la fin.
            let fin_acquitte = self.fin_envoye && t.ack == self.snd_nxt;
            if fin_acquitte {
                n = n.saturating_sub(1);
            }
            self.acquitter_octets(n);
            self.snd_una = t.ack;
            e.place = true;
            e.a_emettre = true;
            if fin_acquitte {
                match self.etat {
                    Etat::FinAttente1 => self.passer(Etat::FinAttente2, &mut e),
                    Etat::Fermeture => self.passer(Etat::TempsAttente, &mut e),
                    Etat::DernierAck => {
                        self.passer(Etat::Fermee, &mut e);
                        return e;
                    }
                    _ => {}
                }
            }
        }
        // La fenêtre de l'autre (RFC 9293, 3.10.7.4, SND.WL1/WL2).
        if avant(self.snd_wl1, t.seq) || (self.snd_wl1 == t.seq && !avant(t.ack, self.snd_wl2)) {
            if self.snd_wnd == 0 && t.fenetre != 0 {
                e.a_emettre = true;
            }
            self.snd_wnd = t.fenetre as u32;
            self.snd_wl1 = t.seq;
            self.snd_wl2 = t.ack;
        }
        // 7. Le texte : dans l'ordre seulement (la file hors d'ordre vient
        // au commit suivant) ; ce qui a déjà été reçu est retiré du début.
        // Pour une lecture fermée, en FIN_WAIT, des données neuves coupent
        // la connexion : RST, comme BSD et Linux (« RFC 793 says to queue
        // data in these states, RFC 1122 says we MUST send a reset »,
        // `tcp_rcv_state_process`) ; l'autre apprend que ce qu'il envoie ne
        // sera jamais lu.
        if self.lecture_fermee
            && matches!(self.etat, Etat::FinAttente1 | Etat::FinAttente2)
            && longueur_charge > 0
            && apres(seq.wrapping_add(longueur_charge), self.rcv_nxt)
        {
            self.rst_du = Some((t.ack, 0, tcp::RST));
            self.finir(ECONNRESET, &mut e);
            e.a_emettre = true;
            return e;
        }
        if longueur_charge > 0 && matches!(self.etat, Etat::Etablie | Etat::FinAttente1 | Etat::FinAttente2) {
            if apres(t.seq, self.rcv_nxt) {
                // Un trou : ce segment est jeté, l'ACK redit ce qu'on
                // attend.
                self.ack_du = true;
                e.a_emettre = true;
                return e;
            }
            let deja = self.rcv_nxt.wrapping_sub(t.seq) as usize;
            charge.avancer(deja);
            let n = charge.octets().len();
            if n > 0 {
                // La fenêtre annoncée est une promesse : ce qui y tient est
                // gardé, même si sa taille vraie dépasse un peu SO_RCVBUF
                // (de petits segments occupent plus que prévu : Linux les
                // recopie alors en gros blocs, le « collapse » de
                // `tcp_prune_queue`, que nous n'avons pas). Au-delà du
                // double de SO_RCVBUF, la mémoire prime : jeté.
                if self.taille_vraie_reception + charge.taille_vraie() > 2 * self.rcvbuf
                    || self.reception.try_reserve(1).is_err()
                {
                    // Plus de place : jeté (l'autre le renverra).
                    self.ack_du = true;
                    e.a_emettre = true;
                    return e;
                }
                self.taille_vraie_reception += charge.taille_vraie();
                self.octets_reception += n;
                self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
                self.reception.push_back(charge);
                e.lisible = true;
            }
            self.ack_du = true;
            e.a_emettre = true;
        }
        // 8. FIN, s'il arrive à son tour.
        if fin && t.seq.wrapping_add(longueur_charge) == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.fin_recue = true;
            self.ack_du = true;
            e.a_emettre = true;
            e.lisible = true;
            match self.etat {
                Etat::Etablie => self.passer(Etat::AttenteFermeture, &mut e),
                Etat::FinAttente1 => {
                    // Notre FIN acquitté avec : TIME_WAIT ; sinon CLOSING.
                    let n = if self.fin_envoye && self.snd_una == self.snd_nxt { Etat::TempsAttente } else { Etat::Fermeture };
                    self.passer(n, &mut e);
                }
                Etat::FinAttente2 => self.passer(Etat::TempsAttente, &mut e),
                _ => {}
            }
        }
        self.annoncer();
        e
    }

    /// Une erreur ICMP pour cette connexion (`tcp_v4_err`) : `erreur` est
    /// l'errno que dit `icmp_err_convert`. Avant la fin de la poignée de
    /// main, toute erreur ferme la connexion (un `connect` la rend
    /// aussitôt : la machine est injoignable, inutile d'attendre) ;
    /// ensuite, elle n'est que « douce » (rendue si la connexion abandonne,
    /// au commit suivant), sauf avec IP_RECVERR (`recverr`), où elle est
    /// rendue tout de suite. (`fatale`, ce que dit `icmp_err_convert`, ne
    /// change rien pour TCP : Linux ne s'en sert que pour UDP et les
    /// sockets brutes.)
    pub fn erreur_icmp(&mut self, erreur: i32, _fatale: bool, recverr: bool) -> Effets {
        let mut e = Effets::default();
        match self.etat {
            Etat::SynEnvoye | Etat::SynRecu => self.finir(erreur, &mut e),
            Etat::Fermee | Etat::TempsAttente => {}
            _ if recverr => {
                self.erreur = erreur;
                e.lisible = true;
                e.place = true;
            }
            _ => self.erreur_douce = erreur,
        }
        e
    }

    // --- Ce qu'il faut envoyer ---

    /// L'en-tête d'un segment de cette connexion.
    fn entete(&self, seq: u32, drapeaux: u8) -> Tcp {
        Tcp {
            source: self.port_local,
            destination: self.port_distant,
            seq,
            ack: if drapeaux & tcp::ACK != 0 { self.rcv_nxt } else { 0 },
            drapeaux,
            fenetre: if drapeaux & tcp::SYN != 0 { self.fenetre_possible().min(FENETRE_MAX) as u16 } else { self.fenetre() },
            urgent: 0,
            options: tcp::Options::default(),
        }
    }

    /// Rend, par `sortir`, les segments à envoyer maintenant : un RST, le
    /// SYN ou le SYN-ACK, les données que permet la fenêtre de l'autre, le
    /// FIN, l'ACK s'il en faut un et qu'aucun segment ne l'a porté.
    pub fn emettre(&mut self, mut sortir: impl FnMut(Sortant)) {
        if let Some((seq, ack, drapeaux)) = self.rst_du.take() {
            let mut h = self.entete(seq, drapeaux);
            h.ack = ack;
            h.fenetre = 0;
            sortir(Sortant { entete: h, debut: 0, longueur: 0 });
            if self.etat == Etat::Fermee {
                return;
            }
        }
        if self.etat == Etat::Fermee {
            return;
        }
        if self.syn_du {
            self.syn_du = false;
            let drapeaux = if self.etat == Etat::SynRecu { tcp::SYN | tcp::ACK } else { tcp::SYN };
            let mut h = self.entete(self.iss, drapeaux);
            h.options.mss = Some(self.mss_local);
            sortir(Sortant { entete: h, debut: 0, longueur: 0 });
            self.snd_nxt = self.iss.wrapping_add(1);
            self.ack_du = false;
            return;
        }
        if !self.etat.synchronise() {
            // En SYN_RECEIVED, un ACK peut partir (l'ouverture simultanée,
            // un segment inacceptable) ; en SYN_SENT, on ne sait encore rien
            // à acquitter.
            if self.etat == Etat::SynRecu && core::mem::take(&mut self.ack_du) {
                sortir(Sortant { entete: self.entete(self.snd_nxt, tcp::ACK), debut: 0, longueur: 0 });
            }
            return;
        }
        // Les données : à partir de snd_nxt, dans la fenêtre de l'autre,
        // par segments d'au plus un MSS ; le FIN avec le dernier, s'il y a
        // la place.
        let mut envoye = false;
        while !self.fin_envoye {
            let deja = self.envoyes();
            let reste = self.octets_envoi.saturating_sub(deja);
            let en_vol = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            let fenetre_libre = (self.snd_wnd as usize).saturating_sub(en_vol);
            let n = reste.min(fenetre_libre).min(self.mss as usize);
            let fin_maintenant = self.fin_voulue && n == reste;
            if n == 0 && !fin_maintenant {
                break;
            }
            let mut drapeaux = tcp::ACK;
            if n > 0 {
                drapeaux |= tcp::PSH;
            }
            if fin_maintenant {
                drapeaux |= tcp::FIN;
            }
            let h = self.entete(self.snd_nxt, drapeaux);
            sortir(Sortant { entete: h, debut: deja, longueur: n });
            self.snd_nxt = self.snd_nxt.wrapping_add(n as u32 + u32::from(fin_maintenant));
            self.fin_envoye |= fin_maintenant;
            envoye = true;
        }
        if self.ack_du && !envoye {
            let h = self.entete(self.snd_nxt, tcp::ACK);
            sortir(Sortant { entete: h, debut: 0, longueur: 0 });
        }
        self.ack_du = false;
    }
}

/// La réponse à un segment qui n'a pas de connexion (`tcp_v4_send_reset`,
/// RFC 9293 3.10.7.1) : rien pour un RST ; sinon un RST, dont le numéro
/// est l'ACK du segment s'il en avait un, ou 0 avec un ACK de tout ce qu'il
/// portait.
pub fn reponse_sans_connexion(t: &Tcp, longueur_charge: usize) -> Option<Tcp> {
    if t.drapeaux & tcp::RST != 0 {
        return None;
    }
    let mut r = Tcp { source: t.destination, destination: t.source, ..Tcp::default() };
    if t.drapeaux & tcp::ACK != 0 {
        r.seq = t.ack;
        r.drapeaux = tcp::RST;
    } else {
        let n = longueur_charge as u32 + u32::from(t.drapeaux & tcp::SYN != 0) + u32::from(t.drapeaux & tcp::FIN != 0);
        r.ack = t.seq.wrapping_add(n);
        r.drapeaux = tcp::RST | tcp::ACK;
    }
    Some(r)
}
