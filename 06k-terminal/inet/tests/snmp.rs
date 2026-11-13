//! Le texte de /proc/net/snmp (inet::snmp), comparé à celui de Linux 6.18
//! (`cat /proc/net/snmp` sur l'hôte : les noms, au caractère près).

use inet::snmp::{Icmp, Ip, Mib, Udp};

fn texte(m: &Mib) -> String {
    let mut t = String::new();
    m.ecrire(64, &mut t).unwrap();
    t
}

const IP: &str = "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits\n";
const ICMP: &str = "Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n";
const TCP: &str = "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n";
const UDP: &str = "InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n";

fn zeros(n: usize) -> String {
    " 0".repeat(n)
}

/// À zéro : IcmpMsg absent, les quatre valeurs fixes de TCP (MaxConn signé).
#[test]
fn a_zero() {
    static M: Mib = Mib::new();
    let attendu = format!(
        "{IP}Ip: 2 64{}\n{ICMP}Icmp:{}\n{TCP}Tcp: 1 200 120000 -1{}\nUdp: {UDP}Udp:{}\nUdpLite: {UDP}UdpLite:{}\n",
        zeros(18), zeros(29), zeros(11), zeros(9), zeros(9)
    );
    assert_eq!(texte(&M), attendu);
}

/// Chaque compteur à sa place ; les genres ICMP de la MIB lus dans IcmpMsg ;
/// IcmpMsg par paires de lignes de seize, les reçus puis les envoyés.
#[test]
fn les_places() {
    static M: Mib = Mib::new();
    M.ip(Ip::InReceives);
    M.ip(Ip::OutTransmits);
    M.ip(Ip::OutTransmits);
    M.icmp(Icmp::InCsumErrors);
    M.icmp(Icmp::OutRateLimitHost);
    M.udp(Udp::MemErrors);
    // Dix-sept genres reçus, de 0 à 16 ; deux envois d'un écho (8).
    for g in 0..17 {
        M.icmp_entree(g);
    }
    M.icmp_sortie(8);
    M.icmp_sortie(8);
    let t = texte(&M);
    let lignes: Vec<&str> = t.lines().collect();
    assert_eq!(lignes[1], format!("Ip: 2 64 1{} 2", zeros(16)));
    // InMsgs InErrors InCsumErrors, les entrées par genre (3, 11, 12, 4, 5, 8,
    // 0, 13, 14, 17, 18), OutMsgs OutErrors et les limites, les sorties.
    assert_eq!(lignes[3], "Icmp: 0 0 1 1 1 1 1 1 1 1 1 1 0 0 2 0 0 1 0 0 0 0 0 2 0 0 0 0 0");
    let noms: String = (0..16).map(|g| format!(" InType{g}")).collect();
    assert_eq!(lignes[4], format!("IcmpMsg:{noms}"));
    assert_eq!(lignes[5], format!("IcmpMsg:{}", " 1".repeat(16)));
    assert_eq!(lignes[6], "IcmpMsg: InType16 OutType8");
    assert_eq!(lignes[7], "IcmpMsg: 1 2");
    assert_eq!(lignes[8], TCP.trim_end());
    assert_eq!(lignes[11], format!("Udp:{} 1", zeros(8)));
    assert_eq!(lignes.len(), 14);
    assert!(t.ends_with('\n'));
}
