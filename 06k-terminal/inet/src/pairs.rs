//! Les pairs : ce qu'on retient de chaque machine distante (l'`inet_peer` de
//! Linux, net/ipv4/inetpeer.c). Linux y garde plusieurs choses ; une seule
//! nous sert : la limite des erreurs ICMP envoyées à une même machine
//! (`icmp_ratelimit`, `inet_peer_xrlim_allow`), qui vient après la limite
//! globale (icmp.rs du noyau).
//!
//! Pourquoi une limite PAR DESTINATION, en plus de la globale (1000 par
//! seconde) : sans elle, un seul correspondant qui nous bombarde de paquets
//! vers un port fermé (ou une adresse usurpée : la victime est alors celle
//! dont on a pris l'adresse) recevrait jusqu'à 1000 erreurs par seconde, et
//! prendrait à lui seul tout le crédit des autres.
//!
//! LE SEAU À JETONS de Linux : chaque machine a des jetons, gagnés au fil du
//! temps (un par tic de l'horloge de Linux, le jiffy : une milliseconde,
//! HZ = 1000 dans le noyau de référence), plafonnés à six fois le délai
//! (`XRLIM_BURST_FACTOR`) ; une erreur en coûte un délai
//! (`icmp_ratelimit` : une seconde). Une machine nouvelle part pleine
//! (Linux la fait naître 60 s dans le passé, « pour que le premier calcul
//! donne le maximum »), d'où une rafale de six erreurs, puis une par
//! seconde. Le temps est compté en tics entiers, comme les jiffies : un
//! appel dans le même tic que le précédent ne gagne rien.
//!
//! LA TABLE : Linux garde un arbre de toutes les machines vues, sans limite
//! de nombre, que son ramasse-miettes élague (une entrée oubliée après 120
//! à 600 s selon le remplissage, `inet_peer_gc`). Ici, une table de taille
//! fixe, faite d'avance (comme celle des voisins, voisins.rs, et des MTU,
//! pmtu.rs) : une erreur ICMP ne prend pas de mémoire, et un flot de
//! sources usurpées ne la fait pas grossir. Ce qui ne change rien : une
//! machine qu'on n'a pas sollicitée depuis six délais a son seau plein,
//! exactement comme une machine nouvelle ; sa place est libre, et
//! l'oublier ne change aucune décision. Ce qui change : plus de `ENTREES`
//! machines sollicitées en six secondes (un balayage, des sources
//! usurpées), et la plus anciennement sollicitée est oubliée ; elle
//! retrouve une rafale de six plus tôt que chez Linux. Chacun de ces
//! messages reste soumis à la limite globale, qui borne le tout comme chez
//! Linux.
//!
//! Écarté : un arbre ou une table qui grandit (une allocation à chaque
//! machine nouvelle, dans le chemin d'un paquet reçu, pour une différence
//! qui n'apparaît qu'au-delà de 40 machines nouvelles par seconde) ; une
//! table hachée (la recherche linéaire dans 256 entrées coûte moins que le
//! reste du traitement d'un paquet).

/// Un tic de l'horloge de Linux (`HZ` = 1000), en nanosecondes.
const TIC: u64 = 1_000_000;
/// `icmp_ratelimit` : une seconde, en tics.
pub const DELAI: u64 = 1000;
/// `XRLIM_BURST_FACTOR` : le seau tient six délais.
pub const RAFALE: u64 = 6;
/// Les machines retenues à la fois.
pub const ENTREES: usize = 256;

#[derive(Debug, Clone, Copy)]
struct Pair {
    adresse: [u8; 4],
    /// `rate_tokens`, en tics.
    jetons: u64,
    /// `rate_last` : le tic du dernier calcul.
    dernier: u64,
}

pub struct Pairs {
    t: [Option<Pair>; ENTREES],
}

impl Pairs {
    pub const fn new() -> Pairs {
        Pairs { t: [None; ENTREES] }
    }

    /// Peut-on envoyer une erreur ICMP de plus à `adresse`, à l'instant
    /// `maintenant` (en nanosecondes) ? `inet_getpeer_v4` (la machine, créée
    /// si besoin), puis `inet_peer_xrlim_allow` : les jetons gagnés depuis le
    /// dernier calcul, plafonnés ; un délai consommé si le seau le permet.
    pub fn permettre(&mut self, adresse: [u8; 4], maintenant: u64) -> bool {
        let tic = maintenant / TIC;
        let plein = RAFALE * DELAI;
        let i = match self.t.iter().position(|p| p.is_some_and(|p| p.adresse == adresse)) {
            Some(i) => i,
            None => {
                let i = self.place(tic);
                // Née pleine, au tic présent : le premier calcul de Linux
                // (60 s de jetons, plafonnés à six délais).
                self.t[i] = Some(Pair { adresse, jetons: plein, dernier: tic });
                i
            }
        };
        let Some(p) = &mut self.t[i] else { return true };
        let ecoule = tic.saturating_sub(p.dernier);
        if ecoule != 0 {
            p.dernier = tic;
            p.jetons = p.jetons.saturating_add(ecoule).min(plein);
        }
        if p.jetons >= DELAI {
            p.jetons -= DELAI;
            true
        } else {
            false
        }
    }

    /// La place d'une machine nouvelle : une libre ; sinon une dont le seau
    /// s'est rempli depuis (six délais sans être sollicitée : l'oublier ne
    /// change rien) ; sinon la plus anciennement sollicitée.
    fn place(&self, tic: u64) -> usize {
        if let Some(i) = self.t.iter().position(|p| p.is_none_or(|p| tic.saturating_sub(p.dernier) >= RAFALE * DELAI)) {
            return i;
        }
        let mut k = 0;
        for (i, p) in self.t.iter().enumerate() {
            if let (Some(p), Some(x)) = (p, &self.t[k])
                && p.dernier < x.dernier
            {
                k = i;
            }
        }
        k
    }

    /// Le nombre de machines retenues (pour les tests).
    pub fn nombre(&self) -> usize {
        self.t.iter().flatten().count()
    }
}
