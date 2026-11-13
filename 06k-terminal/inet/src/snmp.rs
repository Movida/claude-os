//! Les compteurs de /proc/net/snmp (les soldes d'avant 6k) : les MIB d'IP,
//! d'ICMP, de TCP et d'UDP (les RFC 4293, 4022 et 4113 ; le `net->mib` de
//! Linux, include/uapi/linux/snmp.h), et le texte du fichier, au caractère
//! près (le `snmp_seq_show` de net/ipv4/proc.c). Chaque compteur est
//! incrémenté là où Linux l'incrémente, et la ligne qui le fait cite la
//! fonction de Linux qui le compte : ce module ne dit que leurs noms, leur
//! ordre et leur texte.
//!
//! UN SEUL BLOC pour la machine, des compteurs atomiques que chacun
//! incrémente sans verrou (`Relaxed` : un compteur n'ordonne rien d'autre ;
//! la lecture du fichier n'est pas une photographie, chez Linux non plus).
//! Linux en a un par processeur, sommés à la lecture (`snmp_fold_field`),
//! pour qu'aucune ligne de cache ne passe d'un processeur à l'autre à chaque
//! paquet. Chez nous, tout ce qui arrive passe par une seule tâche (la tâche
//! du réseau) : la réception ne partage rien ; seule l'émission, d'un fil
//! quelconque, paie un `lock xadd` sur une ligne partagée, à côté d'un
//! paquet copié et d'une carte à prévenir. Écarté pour l'instant, donc : un
//! bloc par processeur, et une somme à chaque lecture. Le bloc le deviendra
//! avec des files de réception par processeur (RSS : la carte répartit les
//! paquets entre les processeurs), quand la réception aussi serait partagée.
//! Les 512 compteurs d'IcmpMsg sont globaux chez Linux aussi
//! (`atomic_long_t`).
//!
//! CurrEstab est une jauge (les connexions établies) : un compteur qu'on
//! décrémente aussi (`TCP_DEC_STATS`, `tcp_retirer`).

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};

/// Définit un genre de compteurs : l'énumération, et ses noms tels que les
/// montre le fichier, tirés des noms mêmes des variantes (ceux de Linux,
/// gardés pour qu'on les retrouve dans ses sources) : impossible qu'un nom
/// et sa place divergent.
macro_rules! compteurs {
    ($(#[$doc:meta])* $genre:ident { $($(#[$d:meta])* $nom:ident),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $genre {
            $($(#[$d])* $nom),+
        }

        impl $genre {
            /// Les noms, dans l'ordre du fichier (celui de l'énumération).
            pub const NOMS: &'static [&'static str] = &[$(stringify!($nom)),+];
            const NOMBRE: usize = Self::NOMS.len();
        }
    };
}

compteurs! {
    /// La MIB d'IP (`snmp4_ipstats_list`), sans Forwarding ni DefaultTTL,
    /// qui ne sont pas des compteurs.
    Ip {
        InReceives, InHdrErrors, InAddrErrors, ForwDatagrams, InUnknownProtos, InDiscards, InDelivers,
        OutRequests, OutDiscards, OutNoRoutes, ReasmTimeout, ReasmReqds, ReasmOKs, ReasmFails, FragOKs,
        FragFails, FragCreates, OutTransmits,
    }
}

compteurs! {
    /// La MIB d'ICMP sans les compteurs par genre de message, qui sont ceux
    /// d'IcmpMsg (`icmp_entree`, `icmp_sortie`). Le fichier montre les trois
    /// premiers, les entrées par genre, les quatre suivants, les sorties.
    Icmp {
        InMsgs, InErrors, InCsumErrors, OutMsgs, OutErrors, OutRateLimitGlobal, OutRateLimitHost,
    }
}

compteurs! {
    /// La MIB de TCP (`snmp4_tcp_list`), sans les quatre valeurs fixes du
    /// début (voir `ecrire`).
    Tcp {
        ActiveOpens, PassiveOpens, AttemptFails, EstabResets, CurrEstab, InSegs, OutSegs, RetransSegs,
        InErrs, OutRsts, InCsumErrors,
    }
}

compteurs! {
    /// La MIB d'UDP (`snmp4_udp_list`).
    Udp {
        InDatagrams, NoPorts, InErrors, OutDatagrams, RcvbufErrors, SndbufErrors, InCsumErrors, IgnoredMulti,
        MemErrors,
    }
}

/// Les genres de messages ICMP qu'a la MIB, dans son ordre (`icmpmibmap`) :
/// le nom après « In » ou « Out », et le genre.
const GENRES: [(&str, usize); 11] = [
    ("DestUnreachs", 3), ("TimeExcds", 11), ("ParmProbs", 12), ("SrcQuenchs", 4), ("Redirects", 5), ("Echos", 8),
    ("EchoReps", 0), ("Timestamps", 13), ("TimestampReps", 14), ("AddrMasks", 17), ("AddrMaskReps", 18),
];

/// IcmpMsg : un compteur par genre reçu (0 à 255), puis par genre envoyé
/// (256 à 511 : le genre, plus 0x100).
const MESSAGES: usize = 512;
const SORTIE: usize = 0x100;

/// Les compteurs non nuls d'IcmpMsg tiennent sur des paires de lignes de
/// seize au plus (le PERLINE d'`icmpmsg_put`).
const PAR_LIGNE: usize = 16;

/// Tous les compteurs de la machine.
pub struct Mib {
    ip: [AtomicU64; Ip::NOMBRE],
    icmp: [AtomicU64; Icmp::NOMBRE],
    icmp_msg: [AtomicU64; MESSAGES],
    tcp: [AtomicU64; Tcp::NOMBRE],
    udp: [AtomicU64; Udp::NOMBRE],
}

fn plus(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

fn lire(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

impl Mib {
    /// Un bloc à zéro (un `static` du noyau, ou d'un test).
    pub const fn new() -> Mib {
        Mib {
            ip: [const { AtomicU64::new(0) }; Ip::NOMBRE],
            icmp: [const { AtomicU64::new(0) }; Icmp::NOMBRE],
            icmp_msg: [const { AtomicU64::new(0) }; MESSAGES],
            tcp: [const { AtomicU64::new(0) }; Tcp::NOMBRE],
            udp: [const { AtomicU64::new(0) }; Udp::NOMBRE],
        }
    }

    pub fn ip(&self, c: Ip) {
        plus(&self.ip[c as usize]);
    }

    pub fn icmp(&self, c: Icmp) {
        plus(&self.icmp[c as usize]);
    }

    /// Un message ICMP de genre `genre` est reçu (`ICMPMSGIN_INC_STATS`).
    pub fn icmp_entree(&self, genre: u8) {
        plus(&self.icmp_msg[genre as usize]);
    }

    /// Un message ICMP de genre `genre` part (`icmp_out_count`, compté
    /// quand son paquet est fait : `__ip_make_skb`).
    pub fn icmp_sortie(&self, genre: u8) {
        plus(&self.icmp_msg[SORTIE | genre as usize]);
        self.icmp(Icmp::OutMsgs);
    }

    pub fn tcp(&self, c: Tcp) {
        plus(&self.tcp[c as usize]);
    }

    /// La jauge CurrEstab redescend (`TCP_DEC_STATS`).
    pub fn tcp_retirer(&self, c: Tcp) {
        self.tcp[c as usize].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn udp(&self, c: Udp) {
        plus(&self.udp[c as usize]);
    }

    /// Les valeurs, une à une (les tests).
    pub fn valeur_ip(&self, c: Ip) -> u64 {
        lire(&self.ip[c as usize])
    }

    pub fn valeur_icmp(&self, c: Icmp) -> u64 {
        lire(&self.icmp[c as usize])
    }

    /// `sortie` : les messages envoyés de ce genre, sinon les reçus.
    pub fn valeur_icmp_msg(&self, genre: u8, sortie: bool) -> u64 {
        lire(&self.icmp_msg[if sortie { SORTIE } else { 0 } | genre as usize])
    }

    pub fn valeur_tcp(&self, c: Tcp) -> u64 {
        lire(&self.tcp[c as usize])
    }

    pub fn valeur_udp(&self, c: Udp) -> u64 {
        lire(&self.udp[c as usize])
    }

    /// Le texte de /proc/net/snmp : six groupes (IcmpMsg absent si tous ses
    /// compteurs sont nuls), chacun une ligne de noms et une ligne de
    /// valeurs, qui commencent par le nom du groupe. `ttl` : le réglage
    /// `ip_default_ttl`.
    pub fn ecrire(&self, ttl: u8, t: &mut impl Write) -> fmt::Result {
        // Forwarding : 2, « pas un routeur » (1 : il route ; nous n'avons
        // pas de réglage `ip_forward`).
        t.write_str("Ip: Forwarding DefaultTTL")?;
        noms(t, Ip::NOMS)?;
        write!(t, "\nIp: 2 {ttl}")?;
        valeurs(t, &self.ip)?;

        let (entrees, sorties) = Icmp::NOMS.split_at(3);
        t.write_str("\nIcmp:")?;
        noms(t, entrees)?;
        for (nom, _) in GENRES {
            write!(t, " In{nom}")?;
        }
        noms(t, sorties)?;
        for (nom, _) in GENRES {
            write!(t, " Out{nom}")?;
        }
        t.write_str("\nIcmp:")?;
        valeurs(t, &self.icmp[..3])?;
        for (_, g) in GENRES {
            write!(t, " {}", lire(&self.icmp_msg[g]))?;
        }
        valeurs(t, &self.icmp[3..])?;
        for (_, g) in GENRES {
            write!(t, " {}", lire(&self.icmp_msg[SORTIE | g]))?;
        }

        self.ecrire_icmp_msg(t)?;

        // Les quatre valeurs fixes (`tcp_mib_init`) : RtoAlgorithm 1
        // (« autre » : ni constant, ni l'algorithme de la RFC 793, ni celui
        // de Van Jacobson seul), les bornes du RTO en millisecondes, MaxConn
        // -1 (pas de limite fixe : RFC 2012, le seul compteur signé).
        t.write_str("\nTcp: RtoAlgorithm RtoMin RtoMax MaxConn")?;
        noms(t, Tcp::NOMS)?;
        write!(t, "\nTcp: 1 {} {} -1", crate::tcp::RTO_MIN / 1_000_000, crate::tcp::RTO_MAX / 1_000_000)?;
        valeurs(t, &self.tcp)?;

        t.write_str("\nUdp:")?;
        noms(t, Udp::NOMS)?;
        t.write_str("\nUdp:")?;
        valeurs(t, &self.udp)?;
        // UDP-Lite (RFC 3828) : les noms d'UDP, et des zéros : nous n'en
        // avons pas (Linux montre le groupe même sans socket UDP-Lite).
        t.write_str("\nUdpLite:")?;
        noms(t, Udp::NOMS)?;
        t.write_str("\nUdpLite:")?;
        for _ in Udp::NOMS {
            t.write_str(" 0")?;
        }
        t.write_char('\n')
    }

    /// IcmpMsg (`icmpmsg_put`) : les compteurs non nuls dans l'ordre, les
    /// reçus puis les envoyés, « InType3 », « OutType0 »..., par paires de
    /// lignes de seize au plus. Chaque valeur lue une fois : la ligne des
    /// valeurs dit celles qui ont fait choisir les noms.
    fn ecrire_icmp_msg(&self, t: &mut impl Write) -> fmt::Result {
        let mut paquet = [(0usize, 0u64); PAR_LIGNE];
        let mut n = 0;
        for (k, c) in self.icmp_msg.iter().enumerate() {
            let v = lire(c);
            if v != 0 {
                paquet[n] = (k, v);
                n += 1;
            }
            if n == PAR_LIGNE {
                ligne_icmp_msg(t, &paquet)?;
                n = 0;
            }
        }
        ligne_icmp_msg(t, &paquet[..n])
    }
}

/// « nom1 nom2... », chacun précédé d'une espace.
fn noms(t: &mut impl Write, noms: &[&str]) -> fmt::Result {
    for n in noms {
        write!(t, " {n}")?;
    }
    Ok(())
}

fn valeurs(t: &mut impl Write, compteurs: &[AtomicU64]) -> fmt::Result {
    for c in compteurs {
        write!(t, " {}", lire(c))?;
    }
    Ok(())
}

/// Une paire de lignes d'IcmpMsg ; rien pour aucun compteur.
fn ligne_icmp_msg(t: &mut impl Write, paquet: &[(usize, u64)]) -> fmt::Result {
    if paquet.is_empty() {
        return Ok(());
    }
    t.write_str("\nIcmpMsg:")?;
    for &(k, _) in paquet {
        write!(t, " {}Type{}", if k & SORTIE != 0 { "Out" } else { "In" }, k & 0xFF)?;
    }
    t.write_str("\nIcmpMsg:")?;
    for &(_, v) in paquet {
        write!(t, " {v}")?;
    }
    Ok(())
}
