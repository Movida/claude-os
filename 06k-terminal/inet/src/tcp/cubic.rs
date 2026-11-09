//! CUBIC (RFC 9438), le contrôle de congestion par défaut de Linux
//! (net/ipv4/tcp_cubic.c), avec HyStart, sa sortie du démarrage lent.
//!
//! POURQUOI PAS RENO. Reno regagne un segment par aller-retour après une
//! perte. Sur un long chemin à gros débit (cwnd de 100 000 segments, RTT de
//! 100 ms), revenir au niveau d'avant une perte prendrait une heure et demie :
//! le débit dépend du RTT, et les longues connexions n'atteignent jamais ce
//! que le réseau pourrait porter.
//!
//! L'IDÉE. La fenêtre ne dépend plus des ACK, mais du TEMPS écoulé depuis la
//! dernière réduction, t, le long d'une courbe cubique :
//!     W(t) = C (t - K)³ + Wmax
//! Wmax est la fenêtre au moment de la perte, K le temps qu'il faut pour y
//! revenir, K = ∛(Wmax (1 - β) / C), C = 0,4, β = 717/1024 (la fenêtre après une
//! perte, à 70 % : moins brutal que la moitié de Reno). La courbe monte vite, se
//! fait presque plate en arrivant à Wmax (là où la dernière perte a eu lieu : on
//! reste longtemps au plus haut débit connu), puis, si rien ne se perd, repart de
//! plus en plus vite à la recherche d'un nouveau plafond. Trois retouches :
//!   - la CONVERGENCE RAPIDE : perdre sous l'ancien Wmax veut dire que quelqu'un
//!     d'autre prend de la place sur le chemin : on baisse Wmax en plus, et on
//!     lui en laisse ;
//!   - le mode TCP-FRIENDLY : pour un petit RTT, la courbe grandit moins vite que
//!     ne le ferait Reno, et CUBIC serait lésé face à lui. Il estime donc ce que
//!     Reno aurait comme fenêtre (`tcp_cwnd`), et ne fait jamais moins ;
//!   - la première époque, sans aucune perte connue : au moins 5 % par RTT.
//!
//! COMMENT ÇA S'APPLIQUE. La cwnd grandit toujours dans `tcp_cong_avoid_ai` :
//! d'un segment tous les `cnt` segments acquittés. CUBIC se contente de régler
//! `cnt` pour coller à la courbe (`bictcp_update`) : c'est `pas`, ci-dessous. Tout
//! se calcule en entiers (la racine cubique par une table et une itération de
//! Newton), avec un RTT fixé à 100 ms dans les constantes (`cube_rtt_scale`), et
//! le temps en jiffies de Linux : une décision d'ensemble de cette étape (sack.rs,
//! JIFFY), qui permet de comparer nos valeurs à celles du C de Linux, à l'unité :
//! c'est ce que font les tests, par une table calculée en compilant ces fonctions
//! du noyau dans un petit programme, jamais par une seconde écriture des formules.
//!
//! HYSTART. Le démarrage lent double la cwnd à chaque aller-retour : il finit
//! toujours par une perte en masse, parfois de la moitié de la fenêtre. HyStart
//! (Ha et Rhee, 2008) sort avant la perte, sur deux signes que le chemin est
//! plein, qu'il lit dans la mesure du RTT de chaque ACK :
//!   - le TRAIN D'ACK : des ACK rapprochés (moins de 2 ms entre eux) durent déjà
//!     plus longtemps que la moitié du plus petit RTT (`delay_min`) : ce qu'on
//!     envoie remplit déjà tout le tuyau ;
//!   - le DÉLAI : le plus petit RTT de ce tour (8 mesures) dépasse `delay_min`
//!     de 12,5 % (entre 4 et 16 ms) : une file se forme quelque part.
//! La cwnd reste alors où elle est, qui devient le seuil.
//!
//! Le débit de `pacing` n'entre ici que dans le seuil du train d'ACK. Écarté :
//! `hystart_detect` et les autres paramètres du module : ce sont leurs valeurs
//! par défaut, écrites en constantes, un module de Linux ne se règle qu'en
//! root, et rien chez nous ne le demande.

use super::apres;
use super::sack::JIFFY;

pub(super) const HZ: u32 = 250;
/// β × 1024 (`beta`), et l'échelle de son dénominateur (BICTCP_BETA_SCALE).
const BETA: u32 = 717;
const BETA_ECHELLE: u32 = 1024;
/// Le temps de la courbe compte en 1/1024 s (BICTCP_HZ).
const BICTCP_HZ: u32 = 10;
/// C × 1024 (`bic_scale`).
const C: u32 = 41;
/// C / RTT × 1024, avec un RTT de 100 ms (`cube_rtt_scale`).
const ECHELLE_RTT: u64 = C as u64 * 10;
/// `tcp_friendliness` : combien de segments acquittés font un segment de plus
/// pour le Reno estimé, à un facteur près (`beta_scale`) : 3 (1 - β) / (1 + β),
/// le gain de Reno quand il réduit de β et non de moitié.
const BETA_RENO: u32 = 8 * (BETA_ECHELLE + BETA) / 3 / (BETA_ECHELLE - BETA);
/// 1 / C × 2^(3 BICTCP_HZ) (`cube_factor`) : K = ∛(`CUBE` × (Wmax - cwnd)).
const CUBE: u64 = (1 << (10 + 3 * BICTCP_HZ)) / ECHELLE_RTT;

/// La plus petite cwnd pour HyStart (`hystart_low_window`) : avant, rien à
/// mesurer.
const HYSTART_FENETRE_MIN: u32 = 16;
/// Deux ACK plus proches que ça sont du même train (`hystart_ack_delta_us`).
const HYSTART_ECART_ACK: i32 = 2000;
/// Les mesures d'un tour (HYSTART_MIN_SAMPLES) : le minimum de 8 RTT.
const HYSTART_MESURES: u8 = 8;
/// HYSTART_DELAY_MIN et HYSTART_DELAY_MAX, en µs.
const HYSTART_DELAI_MIN: u32 = 4000;
const HYSTART_DELAI_MAX: u32 = 16000;
/// `sk_gso_max_size` du seuil du train d'ACK (`hystart_ack_delay`) : 65 536 moins
/// `MAX_TCP_HEADER + 1`, soit 320 + 1 octets avec les options de l'hôte. Il couvre
/// les retards que l'agrégation (TSO, GRO) met sur les ACK. Nous n'en faisons pas,
/// mais virtio-net regroupe ses interruptions de la même façon : même marge.
const GSO_MAX: u64 = 65_536 - 321;

/// Ce que CUBIC garde d'une connexion (le `struct bictcp` de Linux, dans son
/// `icsk_ca_priv`).
#[derive(Debug, Clone, Copy)]
pub(super) struct Cubic {
    /// Un segment de plus tous les `cnt` acquittés (`cnt`).
    cnt: u32,
    /// Wmax (`last_max_cwnd`) : 0, aucune perte encore.
    pub(super) wmax: u32,
    /// La cwnd et l'heure, en jiffies, du dernier calcul de `cnt` (`last_cwnd`,
    /// `last_time`).
    derniere_cwnd: u32,
    dernier_calcul: u32,
    /// Le sommet de la courbe (`bic_origin_point`), et le temps pour l'atteindre
    /// (`bic_K`), en 1/1024 s.
    origine: u32,
    k: u32,
    /// Le plus petit RTT, en µs (`delay_min`).
    pub(super) delai_min: u32,
    /// Le début de la courbe, en jiffies ; 0 : à recommencer (`epoch_start`).
    pub(super) debut_epoque: u32,
    /// Les segments acquittés depuis (`ack_cnt`), et la fenêtre qu'aurait Reno
    /// (`tcp_cwnd`).
    acquittes: u32,
    cwnd_reno: u32,
    // HyStart.
    /// Les mesures de ce tour (`sample_cnt`), et la sortie décidée (`found`).
    mesures: u8,
    trouve: bool,
    /// Le début du tour, l'heure du dernier ACK du train (`round_start`,
    /// `last_ack`), en µs ; le numéro qui finit le tour (`end_seq`) ; le plus
    /// petit RTT de ce tour (`curr_rtt`).
    debut_tour: u32,
    dernier_ack: u32,
    pub(super) fin_tour: u32,
    rtt_tour: u32,
}

/// L'heure de la connexion, à la façon de HyStart (`tcp_mstamp`) : des µs sur 32
/// bits, qui reviennent à zéro, comme les jiffies.
fn en_us(maintenant: u64) -> u32 {
    (maintenant / 1000) as u32
}

/// L'heure en jiffies (`tcp_jiffies32`).
pub(super) fn en_jiffies32(maintenant: u64) -> u32 {
    (maintenant / JIFFY) as u32
}

/// `usecs_to_jiffies` : au jiffy supérieur.
fn us_en_jiffies(us: u32) -> u32 {
    let j = 1_000_000 / HZ;
    us.div_ceil(j)
}

/// La racine cubique entière de Linux (`cubic_root`, de Willy Tarreau), à 0,2 %
/// près en moyenne : une table pour les six bits de poids fort, une itération de
/// Newton. Une racine en virgule flottante demanderait de sauver le FPU dans le
/// noyau à chaque perte, et une boucle de Newton dix fois plus de divisions.
pub(super) fn racine_cubique(a: u64) -> u32 {
    // Pour x de 0 à 63 : v = ∛(x << 18) - 1 ; ∛x = (v[x] + 10) >> 6.
    const V: [u8; 64] = [
        0, 54, 54, 54, 118, 118, 118, 118, 123, 129, 134, 138, 143, 147, 151, 156, 157, 161, 164, 168, 170, 173, 176, 179, 181, 185, 187, 190, 192, 194, 197, 199, 200, 202, 204, 206, 209, 211, 213, 215, 217, 219, 221, 222, 224, 225, 227, 229, 231, 232, 234, 236, 237, 239, 240, 242,
        244, 245, 246, 248, 250, 251, 252, 254,
    ];
    let bits = 64 - a.leading_zeros();
    if bits < 7 {
        return (V[a as usize] as u32 + 35) >> 6;
    }
    let b = ((bits * 84) >> 8) - 1;
    // `bits` est la position du plus haut bit : `a >> 3b` tient en 6 bits, et
    // x vaut au moins 4 (la plus petite valeur de la table passé 64, 123, donne
    // (133 << 1) >> 6) : la division est sûre.
    let d = (a >> (b * 3)) as usize;
    let x = ((V[d] as u32 + 10) << b) >> 6;
    // Newton : x' = (2 x + a / x²) / 3, le carré pris pour x (x - 1), et 1/3 pour
    // 341/1024.
    let x = 2u32.wrapping_mul(x).wrapping_add((a / (x as u64 * (x as u64 - 1))) as u32);
    x.wrapping_mul(341) >> 10
}

/// Ce que HyStart lit de la connexion, à chaque ACK.
#[derive(Debug, Clone, Copy)]
pub(super) struct Acquittement {
    pub cwnd: u32,
    pub ssthresh: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    /// Le débit calculé (`sk_pacing_rate`), en octets par seconde.
    pub pacing: u64,
    pub maintenant: u64,
}

impl Cubic {
    pub(super) const fn new() -> Cubic {
        Cubic {
            cnt: 0,
            wmax: 0,
            derniere_cwnd: 0,
            dernier_calcul: 0,
            origine: 0,
            k: 0,
            delai_min: 0,
            debut_epoque: 0,
            acquittes: 0,
            cwnd_reno: 0,
            mesures: 0,
            trouve: false,
            debut_tour: 0,
            dernier_ack: 0,
            fin_tour: 0,
            rtt_tour: 0,
        }
    }

    /// `bictcp_reset` : la courbe et HyStart repartent (pas le tour : voir
    /// `nouveau_tour`).
    fn remettre(&mut self) {
        *self = Cubic { mesures: self.mesures, debut_tour: self.debut_tour, dernier_ack: self.dernier_ack, fin_tour: self.fin_tour, rtt_tour: self.rtt_tour, ..Cubic::new() };
    }

    /// `bictcp_hystart_reset` : un nouveau tour commence.
    fn nouveau_tour(&mut self, snd_nxt: u32, maintenant: u64) {
        self.debut_tour = en_us(maintenant);
        self.dernier_ack = self.debut_tour;
        self.fin_tour = snd_nxt;
        self.rtt_tour = u32::MAX;
        self.mesures = 0;
    }

    /// `cubictcp_init`, à l'établissement.
    pub(super) fn initialiser(&mut self, snd_nxt: u32, maintenant: u64) {
        self.remettre();
        self.nouveau_tour(snd_nxt, maintenant);
    }

    /// `cubictcp_cwnd_event(CA_EVENT_TX_START)` : on repart d'un silence (rien
    /// en vol). Le programme n'avait rien à dire : ce temps ne compte pas pour la
    /// courbe, qui se décale d'autant.
    pub(super) fn depart(&mut self, dernier_envoi: u64, maintenant: u64) {
        let now = en_jiffies32(maintenant);
        let delta = now.wrapping_sub(en_jiffies32(dernier_envoi)) as i32;
        if self.debut_epoque != 0 && delta > 0 {
            self.debut_epoque = self.debut_epoque.wrapping_add(delta as u32);
            if apres(self.debut_epoque, now) {
                self.debut_epoque = now;
            }
        }
    }

    /// `bictcp_update`, ligne à ligne : ce que doit valoir `cnt` pour que la
    /// cwnd suive la courbe. `acquittes`, les segments que couvre cet ACK.
    fn calculer(&mut self, cwnd: u32, acquittes: u32, maintenant: u64) {
        let jiffies = en_jiffies32(maintenant);
        self.acquittes = self.acquittes.wrapping_add(acquittes);
        // Au plus un calcul tous les 1/32 s, tant que la cwnd ne bouge pas.
        if self.derniere_cwnd == cwnd && jiffies.wrapping_sub(self.dernier_calcul) as i32 <= (HZ / 32) as i32 {
            return;
        }
        // Et au plus un par jiffy, sauf une réduction, qui remet `debut_epoque` à
        // 0 pour forcer le calcul.
        if self.debut_epoque == 0 || jiffies != self.dernier_calcul {
            self.derniere_cwnd = cwnd;
            self.dernier_calcul = jiffies;
            if self.debut_epoque == 0 {
                self.debut_epoque = jiffies;
                self.acquittes = acquittes;
                self.cwnd_reno = cwnd;
                if self.wmax <= cwnd {
                    self.k = 0;
                    self.origine = cwnd;
                } else {
                    // K = ∛((Wmax - cwnd) / C), le RTT de 100 ms dans `CUBE`.
                    self.k = racine_cubique(CUBE.wrapping_mul((self.wmax - cwnd) as u64));
                    self.origine = self.wmax;
                }
            }
            // t, en 1/1024 s depuis le début de la courbe, un RTT en avance : la
            // cwnd qu'on règle maintenant sera celle de l'aller-retour suivant.
            let mut t = jiffies.wrapping_sub(self.debut_epoque) as i32 as i64 as u64;
            t = t.wrapping_add(us_en_jiffies(self.delai_min) as u64);
            t <<= BICTCP_HZ;
            t /= HZ as u64;
            let decalage = if t < self.k as u64 { self.k as u64 - t } else { t - self.k as u64 };
            // C/RTT × (t - K)³, en segments. Linux dit qu'il n'y a pas de
            // débordement sous un million de segments ; au-delà, ou après une très
            // longue époque, le calcul revient à zéro, comme le sien, sans panique.
            let delta = (ECHELLE_RTT.wrapping_mul(decalage).wrapping_mul(decalage).wrapping_mul(decalage) >> (10 + 3 * BICTCP_HZ)) as u32;
            let cible = if t < self.k as u64 { self.origine.wrapping_sub(delta) } else { self.origine.wrapping_add(delta) };
            self.cnt = if cible > cwnd { cwnd / (cible - cwnd) } else { cwnd.wrapping_mul(100) };
            // La première époque, sans aucune perte connue : au moins 5 % par RTT.
            if self.wmax == 0 && self.cnt > 20 {
                self.cnt = 20;
            }
        }
        // TCP-friendly : le Reno estimé, un segment tous les `delta` acquittés ;
        // la cwnd ne reste jamais sous lui.
        let delta = (cwnd.wrapping_mul(BETA_RENO)) >> 3;
        while self.acquittes > delta {
            self.acquittes -= delta;
            self.cwnd_reno += 1;
        }
        if self.cwnd_reno > cwnd {
            let max_cnt = cwnd / (self.cwnd_reno - cwnd);
            self.cnt = self.cnt.min(max_cnt);
        }
        // Au plus vite, 1,5 fois par RTT (un segment pour deux acquittés).
        self.cnt = self.cnt.max(2);
    }

    /// `cubictcp_cong_avoid`, après le démarrage lent : tous les combien de
    /// segments acquittés (le `w` de `tcp_cong_avoid_ai`). Toujours au moins 2.
    pub(super) fn pas(&mut self, cwnd: u32, acquittes: u32, maintenant: u64) -> u32 {
        self.calculer(cwnd, acquittes, maintenant);
        self.cnt
    }

    /// `cubictcp_recalc_ssthresh` : une réduction. L'époque est finie ; Wmax, la
    /// cwnd, ou moins si elle n'a pas atteint l'ancien (la convergence rapide :
    /// (1 + β) / 2). Le seuil : β × cwnd, au moins 2.
    pub(super) fn seuil(&mut self, cwnd: u32) -> u32 {
        self.debut_epoque = 0;
        self.wmax = if cwnd < self.wmax { cwnd.wrapping_mul(BETA_ECHELLE + BETA) / (2 * BETA_ECHELLE) } else { cwnd };
        (cwnd.wrapping_mul(BETA) / BETA_ECHELLE).max(2)
    }

    /// `cubictcp_state(TCP_CA_Loss)` : après un RTO, on ne sait plus rien.
    pub(super) fn perte(&mut self, snd_nxt: u32, maintenant: u64) {
        self.remettre();
        self.nouveau_tour(snd_nxt, maintenant);
    }

    /// `hystart_ack_delay` : la marge du train d'ACK, en µs : ce que l'agrégation
    /// peut retarder, d'après le débit ; au plus 1 ms.
    fn marge_train(pacing: u64) -> u32 {
        if pacing == 0 {
            return 0;
        }
        (GSO_MAX * 4 * 1_000_000 / pacing).min(1000) as u32
    }

    /// `hystart_update` : ce RTT, `delai`, dit-il que le chemin est plein ? Rend
    /// vrai pour sortir du démarrage lent (le seuil devient la cwnd).
    fn hystart(&mut self, delai: u32, a: &Acquittement) -> bool {
        if apres(a.snd_una, self.fin_tour) {
            self.nouveau_tour(a.snd_nxt, a.maintenant);
        }
        if a.cwnd < HYSTART_FENETRE_MIN {
            return false;
        }
        let now = en_us(a.maintenant);
        // Le train d'ACK. Le seuil est divisé par deux : sans pacing, une rafale
        // entière part d'un coup (`sk_pacing_status` à SK_PACING_NONE).
        if now.wrapping_sub(self.dernier_ack) as i32 <= HYSTART_ECART_ACK {
            self.dernier_ack = now;
            let seuil = (self.delai_min + Self::marge_train(a.pacing)) >> 1;
            // (Une comparaison non signée chez Linux aussi : s32 contre u32.)
            if now.wrapping_sub(self.debut_tour) > seuil {
                self.trouve = true;
            }
        }
        // Le délai.
        self.rtt_tour = self.rtt_tour.min(delai);
        if self.mesures < HYSTART_MESURES {
            self.mesures += 1;
        } else if self.rtt_tour > self.delai_min + (self.delai_min >> 3).clamp(HYSTART_DELAI_MIN, HYSTART_DELAI_MAX) {
            self.trouve = true;
        }
        self.trouve
    }

    /// `cubictcp_acked`, à chaque ACK qui a une mesure du RTT `rtt_us` : le plus
    /// petit RTT, et HyStart. Rend vrai pour sortir du démarrage lent.
    pub(super) fn acquitte(&mut self, rtt_us: u32, a: &Acquittement) -> bool {
        // Les mesures juste après une reprise sont faussées par ce qui part en
        // rafale (`epoch_start` date de moins d'une seconde).
        if self.debut_epoque != 0 && (en_jiffies32(a.maintenant).wrapping_sub(self.debut_epoque) as i32) < HZ as i32 {
            return false;
        }
        let delai = rtt_us.max(1);
        if self.delai_min == 0 || self.delai_min > delai {
            self.delai_min = delai;
        }
        !self.trouve && a.cwnd < a.ssthresh && self.hystart(delai, a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    /// Le C de `cubic_root` donne ces valeurs (compilé tel quel, dans un petit
    /// programme à part).
    #[test]
    fn racine_comme_le_c_de_linux() {
        for (a, x) in [
            (0u64, 0u32), (1, 1), (2, 1), (3, 1), (7, 2), (8, 2), (26, 3), (27, 3), (63, 4), (64, 4), (65, 4), (100, 5), (127, 5), (128, 5), (1000, 10), (4095, 16), (4096, 16),
            (1_048_576, 101), (1_000_000, 100), (27_000_000, 300), (123_456_789, 497), (1 << 30, 1024), (1 << 40, 10323), (1_000_000_000_000, 9999), (1 << 50, 104_042), (1 << 62, 1_664_674),
            (u64::MAX, 2_641_850), (u64::MAX >> 1, 2_097_068), (804_520_703_100, 9294),
        ] {
            assert_eq!(racine_cubique(a), x, "racine de {a}");
        }
    }

    /// Partout, sans panique (l'indice de la table, la division), et assez juste
    /// pour la courbe : le cube de la racine à moins de 5 % au-delà de 2⁴⁰ (la
    /// taille des valeurs vraies : `CUBE` vaut 2,7 × 10⁹).
    #[test]
    fn racine_partout() {
        for bit in 0..64 {
            for d in [0u64, 1, 2, 3, 5, 9, 17] {
                let a = (1u64 << bit).wrapping_add(d);
                let x = racine_cubique(a) as u128;
                let a = a as u128;
                if bit >= 40 {
                    assert!(x * x * x * 100 <= a * 105 && a * 100 <= x * x * x * 105, "racine de {a} : {x}");
                }
            }
        }
    }

    /// La constante de la courbe, et les autres (`cubictcp_register`, lus dans le
    /// programme de comparaison).
    #[test]
    fn constantes() {
        assert_eq!((BETA_RENO, ECHELLE_RTT, CUBE), (15, 410, 2_681_735_677));
    }

    /// La cwnd qui suit `pas` (`tcp_cong_avoid_ai`), comme le programme de
    /// comparaison.
    fn appliquer(c: &mut Cubic, cwnd: &mut u32, compte: &mut u32, acquittes: u32, t: u64) {
        let w = c.pas(*cwnd, acquittes, t);
        if *compte >= w {
            *compte = 0;
            *cwnd += 1;
        }
        *compte += acquittes;
        if *compte >= w {
            let d = *compte / w;
            *compte -= d * w;
            *cwnd += d;
        }
    }

    /// `bictcp_update` et `cubictcp_recalc_ssthresh` du noyau, dans le programme de
    /// comparaison : une perte à Wmax = 1000, K = 9294/1024 s (la théorie dit
    /// ∛(300 / 0,4) = 9,08 s), une mesure de 50 ms, un ACK tous les 3 jiffies ;
    /// colonne par colonne : le tour, l'heure, cwnd, cnt, K, l'origine, Reno,
    /// acquittés. Autour de K, la courbe se fait plate (cnt 7), puis repart.
    #[test]
    fn courbe_comme_le_c_de_linux() {
        let mut c = Cubic::new();
        c.delai_min = 50_000;
        let s = c.seuil(1000);
        assert_eq!((s, c.wmax), (700, 1000));
        let mut cwnd = s;
        let mut compte = 0;
        let mut t = 1000 * JIFFY;
        let attendu = [
            (0, 1003, 700, 116, 9294, 1000, 700, 1),
            (1, 1006, 700, 116, 9294, 1000, 700, 2),
            (2, 1009, 700, 116, 9294, 1000, 700, 3),
            (250, 1753, 742, 4, 9294, 1000, 700, 251),
            (500, 2503, 804, 4, 9294, 1000, 700, 501),
            (750, 3253, 860, 6, 9294, 1000, 700, 751),
            (1000, 4003, 897, 7, 9294, 1000, 700, 1001),
            (1250, 4753, 935, 6, 9294, 1000, 700, 1251),
            (1500, 5503, 998, 3, 9294, 1000, 700, 1501),
            (1750, 6253, 1114, 2, 9294, 1000, 700, 1751),
        ];
        let mut ligne = 0;
        for i in 0..2000 {
            t += 3 * JIFFY;
            appliquer(&mut c, &mut cwnd, &mut compte, 1, t);
            if ligne < attendu.len() && attendu[ligne].0 == i {
                assert_eq!((i, en_jiffies32(t), cwnd, c.cnt, c.k, c.origine, c.cwnd_reno, c.acquittes), attendu[ligne]);
                ligne += 1;
            }
        }
        assert_eq!(ligne, attendu.len());
        // La convergence rapide : la perte suivante, sous Wmax. (Le C trouve 560 et
        // 680 pour une cwnd de 800, sous Wmax = 1000.)
        c.wmax = 1000;
        assert_eq!((c.seuil(800), c.wmax), (560, 680));
    }

    /// La première époque, sans perte connue : 5 % par RTT au moins (`cnt` = 20).
    /// Le mode TCP-friendly compte en parallèle. Même programme.
    #[test]
    fn premiere_epoque_comme_le_c_de_linux() {
        let mut c = Cubic::new();
        c.delai_min = 100;
        let mut cwnd = 40;
        let mut compte = 0;
        let mut t = 5000 * JIFFY;
        let attendu = [
            (0, 5001, 40, 20, 0, 40, 40, 2),
            (1, 5002, 40, 20, 0, 40, 40, 4),
            (2, 5003, 40, 20, 0, 40, 40, 6),
            (100, 5101, 50, 20, 0, 40, 42, 30),
            (200, 5201, 60, 20, 0, 40, 44, 21),
            (300, 5301, 70, 20, 0, 40, 45, 100),
            (400, 5401, 80, 20, 0, 40, 47, 19),
        ];
        let mut ligne = 0;
        for i in 0..500 {
            t += JIFFY;
            appliquer(&mut c, &mut cwnd, &mut compte, 2, t);
            if ligne < attendu.len() && attendu[ligne].0 == i {
                assert_eq!((i, en_jiffies32(t), cwnd, c.cnt, c.k, c.origine, c.cwnd_reno, c.acquittes), attendu[ligne]);
                ligne += 1;
            }
        }
        assert_eq!(ligne, attendu.len());
    }

    /// Le mode TCP-friendly l'emporte sur la courbe : un petit RTT et une courbe
    /// presque plate (loin de K, Wmax à peine au-dessus) laisseraient `cnt` énorme ;
    /// le Reno estimé, qui gagne sur la cwnd, le borne.
    #[test]
    fn reno_estime_borne_le_pas() {
        let mut c = Cubic::new();
        c.wmax = 1100;
        c.delai_min = 1000;
        let mut t = 1000 * JIFFY;
        // Le premier calcul : une courbe qui démarre presque à plat.
        assert!(c.pas(1000, 1, t) > 50);
        // De quoi faire avancer le Reno estimé bien au-delà de la cwnd : un
        // segment tous les (1000 × 15) >> 3 = 1875 acquittés. (8 jiffies plus
        // tard : avant, la même cwnd ne recalcule rien.)
        t += 8 * JIFFY;
        let p = c.pas(1000, 1875 * 100 + 1, t);
        assert_eq!(c.cwnd_reno, 1100);
        assert_eq!(p, 10, "cwnd / (Reno - cwnd)");
    }

    /// `bictcp_update` ne recalcule pas : au plus une fois par jiffy, et tous les
    /// 1/32 s (7 jiffies) si la cwnd ne bouge pas.
    #[test]
    fn calcul_limite() {
        let mut c = Cubic::new();
        c.wmax = 2000;
        let t = 1000 * JIFFY;
        let p = c.pas(1000, 1, t);
        let k = c.k;
        // Le même jiffy, une autre cwnd : seule la partie Reno passe.
        c.cnt = 9;
        assert_eq!(c.pas(1001, 1, t), 9);
        assert_eq!(c.derniere_cwnd, 1000);
        // La même cwnd, jusqu'à 7 jiffies plus tard : rien ; le 8e, le calcul.
        assert_eq!(c.pas(1000, 1, t + 7 * JIFFY), 9);
        assert_eq!(c.dernier_calcul, 1000);
        assert_ne!(c.pas(1000, 1, t + 8 * JIFFY), 9);
        assert_eq!(c.dernier_calcul, 1008);
        assert_eq!(c.k, k, "K reste celui de l'époque");
        assert!(p > 2);
    }

    /// Le temps de silence ne compte pas pour la courbe (`CA_EVENT_TX_START`) ;
    /// sans époque en cours, rien ; jamais dans le futur.
    #[test]
    fn silence_decale_l_epoque() {
        let mut c = Cubic::new();
        c.depart(100 * JIFFY, 200 * JIFFY);
        assert_eq!(c.debut_epoque, 0);
        c.debut_epoque = 50;
        c.depart(100 * JIFFY, 200 * JIFFY);
        assert_eq!(c.debut_epoque, 150);
        c.debut_epoque = 150;
        c.depart(0, 200 * JIFFY);
        assert_eq!(c.debut_epoque, 200);
    }

    fn acquit(cwnd: u32, t: u64) -> Acquittement {
        Acquittement { cwnd, ssthresh: u32::MAX, snd_una: 100, snd_nxt: 200, pacing: 0, maintenant: t }
    }

    /// HyStart, le train : à partir de 16 segments, des ACK à moins de 2 ms qui
    /// durent plus d'un demi-RTT (5 ms pour 10 ms) font sortir. Moins de 16, rien.
    #[test]
    fn hystart_train() {
        let mut c = Cubic::new();
        c.initialiser(200, 100 * MS);
        assert!(!c.acquitte(10_000, &acquit(15, 200 * MS)));
        // Sous la fenêtre minimale, le tour n'a pas été retouché.
        assert_eq!(c.debut_tour, 100_000);
        c.debut_tour = 200_000;
        c.dernier_ack = 200_000;
        let mut t = 200 * MS;
        for i in 0..3 {
            t += MS;
            assert!(!c.acquitte(10_000, &acquit(20, t)), "tour {i}");
        }
        t += 3 * MS;
        // Trop loin du précédent : ce n'est plus un train.
        assert!(!c.acquitte(10_000, &acquit(20, t)));
        c.dernier_ack = en_us(t);
        t += 2 * MS;
        assert!(c.acquitte(10_000, &acquit(20, t)));
        assert!(c.trouve);
        // La sortie n'est décidée qu'une fois.
        t += MS;
        assert!(!c.acquitte(10_000, &acquit(20, t)));
    }

    /// HyStart, le délai : 8 mesures pour le tour ; un minimum qui dépasse
    /// `delay_min` de 12,5 %, au moins 4 ms, fait sortir.
    #[test]
    fn hystart_delai() {
        let mut c = Cubic::new();
        c.initialiser(200, 0);
        c.delai_min = 10_000;
        // Des ACK espacés de 10 ms : pas un train.
        let mut t = 0;
        for i in 0..8 {
            t += 10 * MS;
            assert!(!c.acquitte(14_100, &acquit(20, t)), "tour {i}");
        }
        // Le minimum du tour, 14,1 ms : plus de 10 + 4 ms.
        t += 10 * MS;
        assert!(c.acquitte(14_100, &acquit(20, t)));
        // 14 ms pile : pas encore. (Un nouveau tour remet les mesures.)
        let mut c = Cubic::new();
        c.initialiser(200, 0);
        c.delai_min = 10_000;
        let mut t = 0;
        for _ in 0..9 {
            t += 10 * MS;
            assert!(!c.acquitte(14_000, &acquit(20, t)));
        }
    }

    /// Un nouveau tour dès que SND.UNA passe la fin du précédent ; juste après
    /// une reprise, la mesure ne vaut rien ; une mesure nulle vaut 1 µs.
    #[test]
    fn hystart_tours_et_mesures_jetees() {
        let mut c = Cubic::new();
        c.initialiser(50, 0);
        c.mesures = 5;
        let mut a = acquit(20, 100 * MS);
        a.snd_una = 51;
        a.snd_nxt = 300;
        c.acquitte(1000, &a);
        assert_eq!((c.fin_tour, c.mesures), (300, 1));
        c.acquitte(0, &a);
        assert_eq!(c.delai_min, 1);
        // L'époque date de moins d'une seconde : rien.
        c.debut_epoque = en_jiffies32(100 * MS);
        c.delai_min = 7;
        assert!(!c.acquitte(1, &acquit(20, 100 * MS + 900 * MS)));
        assert_eq!(c.delai_min, 7);
        assert!(!c.acquitte(1, &acquit(20, 100 * MS + 1000 * MS)));
        assert_eq!(c.delai_min, 1);
    }

    /// La marge du train : au plus 1 ms ; nulle sans débit, et petite à grand
    /// débit.
    #[test]
    fn marge_du_train() {
        assert_eq!(Cubic::marge_train(0), 0);
        assert_eq!(Cubic::marge_train(1000), 1000);
        // 4 × 65 215 octets à 2,6 Go/s : 100 µs.
        assert_eq!(Cubic::marge_train(2_608_600_000), 100);
    }

    /// Une perte par RTO : la courbe et HyStart repartent de rien, Wmax compris.
    #[test]
    fn rto_oublie_tout() {
        let mut c = Cubic::new();
        c.seuil(1000);
        c.delai_min = 5;
        c.trouve = true;
        c.perte(77, 2 * MS);
        assert_eq!((c.wmax, c.delai_min, c.trouve, c.fin_tour, c.debut_tour, c.rtt_tour), (0, 0, false, 77, 2000, u32::MAX));
    }

    /// Tout juste `delta` acquittés : le Reno estimé attend le suivant (`ack_cnt > delta`).
    #[test]
    fn reno_estime_tout_juste() {
        let mut c = Cubic::new();
        c.wmax = 1100;
        c.delai_min = 1000;
        let mut t = 1000 * JIFFY;
        c.pas(1000, 1, t);
        assert_eq!(c.cwnd_reno, 1000);
        t += 8 * JIFFY;
        c.pas(1000, 1874, t);
        assert_eq!(c.cwnd_reno, 1000);
        t += 8 * JIFFY;
        c.pas(1000, 1, t);
        assert_eq!(c.cwnd_reno, 1001);
    }

    /// La convergence rapide, seulement sous l'ancien Wmax : à Wmax tout juste, Wmax reste.
    #[test]
    fn le_seuil_a_wmax_tout_juste() {
        let mut c = Cubic::new();
        c.wmax = 1000;
        c.seuil(1000);
        assert_eq!(c.wmax, 1000);
        c.seuil(999);
        assert_eq!(c.wmax, 999 * (BETA_ECHELLE + BETA) / (2 * BETA_ECHELLE));
    }

    /// HyStart commence à 16 segments, pas après.
    #[test]
    fn hystart_a_la_fenetre_minimale() {
        let mut c = Cubic::new();
        c.initialiser(200, 100 * MS);
        c.delai_min = 10_000;
        c.acquitte(10_000, &acquit(HYSTART_FENETRE_MIN - 1, 100 * MS));
        assert_eq!(c.mesures, 0);
        c.acquitte(10_000, &acquit(HYSTART_FENETRE_MIN, 100 * MS));
        assert_eq!(c.mesures, 1);
    }

    /// Le train d'ACK : plus long que la moitié de `delay_min`, pas tout juste.
    #[test]
    fn hystart_train_tout_juste() {
        let prete = || {
            let mut c = Cubic::new();
            c.initialiser(200, 100 * MS);
            c.delai_min = 10_000;
            c.debut_tour = 200_000;
            c.dernier_ack = 204_999;
            c
        };
        assert!(!prete().acquitte(10_000, &acquit(20, 205 * MS)));
        assert!(prete().acquitte(10_000, &acquit(20, 205 * MS + 1000)));
    }

    /// `tcp_in_slow_start` : à la cwnd tout juste au seuil, ce n'est plus le démarrage lent.
    #[test]
    fn hystart_pas_au_seuil() {
        let mut c = Cubic::new();
        c.initialiser(200, 100 * MS);
        let mut a = acquit(20, 200 * MS);
        a.ssthresh = 20;
        c.acquitte(10_000, &a);
        assert_eq!(c.mesures, 0);
        a.ssthresh = 21;
        c.acquitte(10_000, &a);
        assert_eq!(c.mesures, 1);
    }

    /// `sk_gso_max_size` moins l'en-tête : quatre paquets d'agrégation au débit retenu.
    #[test]
    fn marge_du_train_exacte() {
        assert_eq!(Cubic::marge_train(1_000_000_000), 260);
    }
}
