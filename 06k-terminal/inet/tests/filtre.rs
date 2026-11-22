//! Les filtres des sockets (BPF classique) : la vérification, la mémoire
//! comptée (la longueur de la traduction en eBPF de Linux) et l'exécution,
//! face à ce que Linux 6.18.33 a fait des mêmes programmes (sondes c10,
//! c10c, c10d, c10e du lot 6 des soldes).

use inet::filtre::{self, Carte, Instruction, Refus, Vue, SKF_AD_OFF, SKF_LL_OFF, SKF_NET_OFF};

fn st(code: u16, k: u32) -> Instruction {
    Instruction { code, jt: 0, jf: 0, k }
}
fn ju(code: u16, k: u32, jt: u8, jf: u8) -> Instruction {
    Instruction { code, jt, jf, k }
}
const RET_A: u16 = 0x16;
const RET_K: u16 = 0x06;
const LD_W_ABS: u16 = 0x20;
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_W_IND: u16 = 0x40;
const LD_B_IND: u16 = 0x50;
const LD_LEN: u16 = 0x80;
const LD_IMM: u16 = 0x00;
const LDX_IMM: u16 = 0x01;
const LD_MEM: u16 = 0x60;
const LDX_MEM: u16 = 0x61;
const LDX_LEN: u16 = 0x81;
const LDX_MSH: u16 = 0xb1;
const ST: u16 = 0x02;
const ADD_K: u16 = 0x04;
const DIV_K: u16 = 0x34;
const DIV_X: u16 = 0x3c;
const MOD_X: u16 = 0x9c;
const LSH_K: u16 = 0x64;
const LSH_X: u16 = 0x6c;
const RSH_X: u16 = 0x7c;
const AND_K: u16 = 0x54;
const NEG: u16 = 0x84;
const TAX: u16 = 0x07;
const TXA: u16 = 0x87;
const JA: u16 = 0x05;
const JEQ_K: u16 = 0x15;
const JGT_K: u16 = 0x25;
const JGE_K: u16 = 0x35;
const JGE_X: u16 = 0x3d;
const JSET_K: u16 = 0x45;
const JSET_X: u16 = 0x4d;

fn ad(n: i32) -> u32 {
    (SKF_AD_OFF + n) as u32
}

/// La mémoire que compte le programme, ou son refus.
fn memoire(p: &[Instruction]) -> Result<usize, Refus> {
    filtre::verifier(p)?;
    filtre::longueur_convertie(p).map(filtre::taille)
}

#[test]
fn les_refus_de_la_verification() {
    let refuses: &[&[Instruction]] = &[
        &[],
        &[st(DIV_K, 0), st(RET_K, 0)],
        &[st(LSH_K, 32), st(RET_K, 0)],
        &[st(LD_MEM, 0), st(RET_K, 0)],
        &[st(LD_MEM, 16), st(RET_K, 0)],
        &[st(LD_IMM, 0)],
        &[st(0xffff, 0), st(RET_K, 0)],
        &[ju(JA, 1, 0, 0), st(RET_K, 0)],
        &[st(LD_W_ABS, ad(68)), st(RET_K, 0)],
        &[st(LD_W_ABS, ad(64)), st(RET_A, 0)],
        // ret x, ld h #k : un bit de trop.
        &[st(0x0e, 0)],
        &[st(0x08, 0), st(RET_A, 0)],
        // Un saut conditionnel hors du programme.
        &[ju(JEQ_K, 0, 1, 0), st(RET_A, 0)],
        // M[0] écrit sur une seule branche.
        &[ju(JEQ_K, 0, 0, 1), st(ST, 0), st(LD_MEM, 0), st(RET_A, 0)],
        // Derrière un RET, la passe garde ce qui précédait (rien d'écrit).
        &[st(RET_K, 0), st(LD_MEM, 0), st(RET_A, 0)],
        // -8 : au-dessus de SKF_AD_OFF, pas une extension.
        &[st(LD_B_ABS, (-8i32) as u32), st(RET_A, 0)],
    ];
    for p in refuses {
        assert_eq!(filtre::verifier(p), Err(Refus::Invalide), "{p:?}");
    }
    let trop = vec![st(RET_K, 0); filtre::MAX_INSTRUCTIONS + 1];
    assert_eq!(filtre::verifier(&trop), Err(Refus::Invalide));
    // Acceptés : M[0] écrit sur les deux branches ; une lecture IND au-delà
    // de SKF_AD_OFF (seul ABS est vérifié) ; SKF_NET_OFF ; 0x80000000.
    let acceptes: &[&[Instruction]] = &[
        &[ju(JEQ_K, 0, 0, 1), st(ST, 0), st(ST, 0), st(LD_MEM, 0), st(RET_A, 0)],
        &[st(LD_B_IND, ad(68)), st(RET_A, 0)],
        &[st(LD_B_ABS, SKF_NET_OFF as u32), st(RET_A, 0)],
        &[st(LD_B_ABS, 0x8000_0000), st(RET_A, 0)],
        &[st(LD_B_ABS, ad(60)), st(RET_A, 0)],
    ];
    for p in acceptes {
        assert_eq!(filtre::verifier(p), Ok(()), "{p:?}");
    }
}

#[test]
fn la_memoire_comptee_est_celle_de_linux() {
    // (programme, SO_MEMINFO[6] mesuré sous Linux)
    let cas: Vec<(Vec<Instruction>, usize)> = vec![
        (vec![st(RET_K, 0)], 136),
        (vec![st(RET_A, 0)], 128),
        (vec![st(LD_W_ABS, 0), st(RET_A, 0)], 264),
        (vec![st(LD_H_ABS, 0), st(RET_A, 0)], 264),
        (vec![st(LD_B_ABS, 0), st(RET_A, 0)], 256),
        (vec![st(LDX_MSH, 0), st(LD_W_IND, 0), st(RET_A, 0)], 368),
        (vec![st(LD_LEN, 0), st(RET_A, 0)], 136),
        (vec![st(LD_IMM, 5), st(ST, 0), st(LDX_MEM, 0), st(RET_A, 0)], 152),
        (vec![st(DIV_X, 0), st(RET_A, 0)], 168),
        (vec![st(MOD_X, 0), st(RET_A, 0)], 168),
        (vec![st(NEG, 0), st(RET_A, 0)], 136),
        (vec![st(TAX, 0), st(RET_A, 0)], 136),
        (vec![ju(JEQ_K, 1, 0, 1), st(RET_K, 1), st(RET_K, 0)], 160),
        (vec![ju(JEQ_K, 1, 1, 0), st(RET_K, 1), st(RET_K, 0)], 160),
        (vec![ju(JGT_K, 1, 1, 1), st(RET_K, 1), st(RET_K, 0), st(RET_K, 2)], 184),
        (vec![ju(JSET_X, 0, 0, 1), st(RET_K, 1), st(RET_K, 0)], 168),
        (vec![ju(JA, 1, 0, 0), st(RET_K, 1), st(RET_K, 0)], 160),
        (vec![st(LD_B_ABS, SKF_NET_OFF as u32), st(RET_A, 0)], 224),
        (vec![st(LD_B_ABS, SKF_LL_OFF as u32), st(RET_A, 0)], 224),
        (vec![ju(JEQ_K, 0xffff_ffff, 0, 1), st(RET_K, 1), st(RET_K, 0)], 168),
        (vec![ju(JSET_K, 1, 0, 1), st(RET_K, 1), st(RET_K, 0)], 168),
        (vec![ju(JGE_K, 1, 0, 1), st(RET_K, 1), st(RET_K, 0)], 160),
        (vec![ju(JGE_X, 1, 1, 0), st(RET_K, 1), st(RET_K, 0)], 160),
        (vec![ju(JEQ_K, 1, 0, 0), st(RET_K, 1), st(RET_K, 0)], 160),
        (vec![st(LD_B_IND, 5), st(RET_A, 0)], 232),
        (vec![st(LD_H_ABS, 5), st(RET_A, 0)], 272),
        (vec![st(LD_W_ABS, 0x8000_0000), st(RET_A, 0)], 224),
        (vec![st(LD_W_ABS, 40000), st(RET_A, 0)], 288),
        (vec![st(LD_H_ABS, 32767), st(RET_A, 0)], 272),
        (vec![st(LD_H_ABS, 32768), st(RET_A, 0)], 288),
        (vec![st(LD_B_ABS, ad(0)), st(RET_A, 0)], 144),
        (vec![st(LDX_LEN, 0), st(TXA, 0), st(RET_A, 0)], 144),
        (vec![st(LDX_MSH, 40000), st(RET_A, 0)], 328),
        (vec![st(LD_W_ABS, 40000), st(LDX_MSH, 3), st(RET_A, 0)], 440),
    ];
    for (p, attendu) in &cas {
        assert_eq!(memoire(p), Ok(*attendu), "{p:?}");
    }
    // Les extensions, de ad+0 à ad+60, chacune suivie de `ret a`.
    let extensions = [144, 144, 160, 160, 160, 136, 136, 160, 136, 160, 136, 136, 152, 160, 160, 144];
    for (n, attendu) in extensions.iter().enumerate() {
        assert_eq!(memoire(&[st(LD_W_ABS, ad(4 * n as i32)), st(RET_A, 0)]), Ok(*attendu), "ad+{}", 4 * n);
    }
    // n - 1 additions, puis ret a.
    for (n, attendu) in [(2, 136), (16, 248), (256, 2168), (4096, 32888)] {
        let mut p = vec![st(ADD_K, 1); n - 1];
        p.push(st(RET_A, 0));
        assert_eq!(memoire(&p), Ok(attendu), "{n}");
    }
    assert_eq!(memoire(&vec![st(RET_K, 0); 4096]), Ok(65656));
}

/// `n` lectures longues (16 instructions traduites chacune).
fn longues(n: usize) -> Vec<Instruction> {
    vec![st(LD_W_ABS, 40000); n]
}

#[test]
fn les_sauts_que_la_traduction_refuse() {
    // 1023 instructions (1022 lectures longues et ret a) : 130976 (la mémoire des options
    // presque pleine).
    let mut p = longues(1022);
    p.push(st(RET_A, 0));
    assert_eq!(memoire(&p), Ok(130_976));
    // Un saut au-delà de 32767 instructions traduites.
    for (k, attendu) in [(2047usize, true), (2048, false), (2100, false)] {
        let mut p = vec![ju(JA, k as u32, 0, 0)];
        p.extend(longues(k));
        p.push(st(RET_A, 0));
        assert_eq!(memoire(&p).is_ok(), attendu, "ja {k}");
    }
    // Un saut placé au-delà de la 32768e (la première passe de Linux) : ja 0.
    for (n, attendu) in [(2047usize, true), (2048, false)] {
        let mut p = longues(n);
        p.push(ju(JA, 0, 0, 0));
        p.push(st(RET_A, 0));
        assert_eq!(memoire(&p).is_ok(), attendu, "{n} longues, ja 0");
    }
    let mut p = longues(2048);
    p.push(st(RET_A, 0));
    assert!(memoire(&p).is_ok());
    // jeq #-1 (mov, puis jne : la deuxième à 32757) ; jgt #-1 jt 1 jf 1 (mov, jgt, ja).
    let mut p = longues(2046);
    p.push(st(LD_W_ABS, 100));
    p.push(ju(JEQ_K, 0xffff_ffff, 0, 0));
    p.push(st(RET_A, 0));
    assert!(memoire(&p).is_ok());
    p.truncate(p.len() - 2);
    p.extend([ju(JGT_K, 0xffff_ffff, 1, 1), st(RET_A, 0), st(RET_A, 0), st(RET_A, 0)]);
    assert!(memoire(&p).is_ok());
    // Trois instructions de plus (ld [100], ld [100], ld #1 : 27) : le ja passe 32768.
    p.truncate(p.len() - 4);
    p.extend([st(LD_W_ABS, 100), st(LD_W_ABS, 100), st(LD_IMM, 1), ju(JA, 0, 0, 0), st(RET_A, 0)]);
    assert_eq!(memoire(&p), Err(Refus::Invalide));
}

/// Un datagramme UDP par lo, tel que le voit le filtre de la socket qui le
/// reçoit : la trame Ethernet de lo (adresses nulles), l'en-tête IPv4,
/// l'en-tête UDP, puis `n` octets ('a' + i % 26).
fn trame_udp(n: usize) -> Vec<u8> {
    let mut t = vec![0u8; 12];
    t.extend([0x08, 0x00]);
    let total = (20 + 8 + n) as u16;
    t.extend([0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1]);
    let udp = (8 + n) as u16;
    t.extend([0xa5, 0x6b, 0x30, 0x39, (udp >> 8) as u8, udp as u8, 0, 0]);
    t.extend((0..n).map(|i| b'a' + (i % 26) as u8));
    t
}

fn vue_udp(t: &[u8]) -> Vue<'_> {
    Vue {
        octets: t, donnees: 34, reseau: 14, liaison: Some(0), protocole: 0x0800, genre: 0,
        carte: Some(Carte { index: 1, genre: 772 }), marque: 0, file: 0, hachage: 0, processeur: 0, charge: 8,
    }
}

fn vue_unix(t: &[u8]) -> Vue<'_> {
    Vue {
        octets: t, donnees: 0, reseau: 0, liaison: None, protocole: 0, genre: 0, carte: None, marque: 0, file: 0,
        hachage: 0, processeur: 0, charge: 0,
    }
}

fn executer(p: &[Instruction], v: &Vue) -> u32 {
    assert_eq!(filtre::verifier(p), Ok(()), "{p:?}");
    filtre::executer(p, v, &mut || 7)
}

/// La valeur que lit une instruction, puis `ret a`.
fn lu(i: Instruction, v: &Vue) -> u32 {
    executer(&[i, st(RET_A, 0)], v)
}

#[test]
fn les_lectures_du_paquet() {
    let t = trame_udp(600);
    let v = vue_udp(&t);
    assert_eq!(lu(st(LD_B_ABS, 0), &v), 0xa5);
    assert_eq!(lu(st(LD_H_ABS, 0), &v), 0xa56b);
    assert_eq!(lu(st(LD_B_ABS, SKF_NET_OFF as u32), &v), 69);
    assert_eq!(lu(st(LD_B_ABS, (SKF_NET_OFF + 9) as u32), &v), 17);
    assert_eq!(lu(st(LD_H_ABS, (SKF_NET_OFF + 2) as u32), &v), 628);
    assert_eq!(lu(st(LD_B_ABS, (SKF_NET_OFF + 20) as u32), &v), 0xa5);
    assert_eq!(lu(st(LD_B_ABS, SKF_LL_OFF as u32), &v), 0);
    assert_eq!(lu(st(LD_H_ABS, (SKF_LL_OFF + 12) as u32), &v), 0x0800);
    assert_eq!(lu(st(LD_B_ABS, (SKF_LL_OFF + 14) as u32), &v), 69);
    assert_eq!(lu(st(LD_LEN, 0), &v), 608);
    assert_eq!(lu(st(LD_B_ABS, 599), &v), b't' as u32);
    // Hors du paquet : le programme rend 0 (le paquet jeté).
    assert_eq!(lu(st(LD_B_ABS, 608), &v), 0);
    assert_eq!(lu(st(LD_W_ABS, 605), &v), 0);
    assert_eq!(lu(st(LD_B_ABS, 0x8000_0000), &v), 0);
    assert_eq!(executer(&[st(LDX_IMM, (-8i32) as u32), st(LD_B_IND, 0), st(RET_A, 0)], &v), 0);
    assert_eq!(executer(&[st(LDX_IMM, 8), st(LD_B_IND, 591), st(RET_A, 0)], &v), b't' as u32);
    assert_eq!(executer(&[st(LDX_MSH, SKF_NET_OFF as u32), st(TXA, 0), st(RET_A, 0)], &v), 20);
    assert_eq!(executer(&[st(LDX_IMM, 0), st(DIV_X, 0), st(RET_A, 0)], &v), 0);
    assert_eq!(executer(&[st(LDX_IMM, 0), st(LD_IMM, 5), st(MOD_X, 0), st(RET_A, 0)], &v), 0);
    // AF_UNIX : l'en-tête de réseau est le début du message ; pas de liaison.
    let m = trame_udp(600)[42..].to_vec();
    let u = vue_unix(&m);
    assert_eq!(lu(st(LD_B_ABS, SKF_NET_OFF as u32), &u), b'a' as u32);
    assert_eq!(lu(st(LD_B_ABS, (SKF_NET_OFF + 9) as u32), &u), b'j' as u32);
    assert_eq!(lu(st(LD_B_ABS, SKF_LL_OFF as u32), &u), 0);
    assert_eq!(executer(&[st(LDX_MSH, SKF_NET_OFF as u32), st(TXA, 0), st(RET_A, 0)], &u), 4);
    assert_eq!(lu(st(LD_LEN, 0), &u), 600);
}

#[test]
fn les_extensions() {
    let t = trame_udp(600);
    let v = vue_udp(&t);
    let avec = |n: i32, v: &Vue| executer(&[st(LDX_IMM, 3), st(LD_IMM, 0x1234), st(LD_W_ABS, ad(n)), st(RET_A, 0)], v);
    // Mesuré pour UDP par lo, dans l'ordre de ad+0 à ad+60 (sans ad+56, le hasard).
    let attendu = [2048, 0, 1, 0, 0, 0, 0, 772, 0, 0, 0x1234 ^ 3, 0, 0, 8, 7, 0];
    for (n, a) in attendu.iter().enumerate() {
        assert_eq!(avec(4 * n as i32, &v), *a, "ad+{}", 4 * n);
    }
    // ldb [ad+0] : les 16 bits du protocole.
    assert_eq!(lu(st(LD_B_ABS, ad(0)), &v), 2048);
    // Sans carte (AF_UNIX), ifindex et hatype sortent en rendant A.
    let m = vec![b'x'; 600];
    let u = vue_unix(&m);
    assert_eq!(avec(8, &u), 0x1234);
    assert_eq!(avec(28, &u), 0x1234);
    assert_eq!(avec(0, &u), 0);
    assert_eq!(avec(52, &u), 0);
}

#[test]
fn les_attributs_netlink() {
    // La charge (après les 8 octets d'UDP) : (8, 7) à 4, puis (12, 9) à 12,
    // qui contient des zéros (le (8, 2) à 20 n'est pas dans ses données).
    let mut t = trame_udp(64);
    let charge = &mut t[42..];
    charge.fill(0);
    charge[4..8].copy_from_slice(&[8, 0, 7, 0]);
    charge[12..16].copy_from_slice(&[12, 0, 9, 0]);
    charge[20..24].copy_from_slice(&[8, 0, 2, 0]);
    let v = vue_udp(&t);
    let nla = |a: u32, x: u32, n: i32| executer(&[st(LD_IMM, a), st(LDX_IMM, x), st(LD_W_ABS, ad(n)), st(RET_A, 0)], &v);
    assert_eq!(nla(12, 9, 12), 20);
    assert_eq!(nla(12, 7, 12), 12);
    assert_eq!(nla(20, 2, 16), 0);
    assert_eq!(nla(20, 9, 12), 20);
    assert_eq!(nla(0x1234, 9, 12), 0);
    // Dans (12, 9) : ses données (de 24 à 28) commencent par (4, 3).
    t[42 + 16..42 + 20].copy_from_slice(&[4, 0, 3, 0]);
    let v = vue_udp(&t);
    let nla = |a: u32, x: u32, n: i32| executer(&[st(LD_IMM, a), st(LDX_IMM, x), st(LD_W_ABS, ad(n)), st(RET_A, 0)], &v);
    assert_eq!(nla(20, 3, 16), 24);
}

#[test]
fn les_calculs_et_les_sauts() {
    let t = trame_udp(10);
    let v = vue_udp(&t);
    // Décalages masqués à 31 bits (mesuré).
    assert_eq!(executer(&[st(LDX_IMM, 33), st(LD_IMM, 1), st(LSH_X, 0), st(RET_A, 0)], &v), 2);
    assert_eq!(executer(&[st(LDX_IMM, 33), st(LD_IMM, 64), st(RSH_X, 0), st(RET_A, 0)], &v), 32);
    assert_eq!(executer(&[st(LD_IMM, 5), st(NEG, 0), st(RET_A, 0)], &v), (-5i32) as u32);
    assert_eq!(executer(&[st(LD_IMM, 0xff0f), st(AND_K, 0xf0), st(RET_A, 0)], &v), 0);
    // Comparaisons sans signe, sur 32 bits.
    let p = [st(LD_IMM, 0xffff_fffe), ju(JGT_K, 0xffff_fffd, 0, 1), st(RET_K, 1), st(RET_K, 2)];
    assert_eq!(executer(&p, &v), 1);
    let p = [st(LD_IMM, 6), ju(JSET_K, 4, 0, 1), st(RET_K, 1), st(RET_K, 2)];
    assert_eq!(executer(&p, &v), 1);
    let p = [st(LD_IMM, 6), ju(JGE_K, 7, 0, 1), st(RET_K, 1), st(RET_K, 2)];
    assert_eq!(executer(&p, &v), 2);
    let p = [ju(JA, 1, 0, 0), st(RET_K, 1), st(RET_K, 3)];
    assert_eq!(executer(&p, &v), 3);
    let p = [st(LD_IMM, 9), st(ST, 15), st(LD_IMM, 0), st(LDX_MEM, 15), st(TXA, 0), st(RET_A, 0)];
    assert_eq!(executer(&p, &v), 9);
}

#[test]
fn le_decodage() {
    let octets = [0x06, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x15, 0x00, 0x01, 0x02, 0x34, 0x12, 0x00, 0x00];
    let p = filtre::decoder(&octets).unwrap();
    assert_eq!(p, vec![st(RET_K, 0xffff), ju(JEQ_K, 0x1234, 1, 2)]);
    assert_eq!(p[1].octets(), octets[8..16]);
}
