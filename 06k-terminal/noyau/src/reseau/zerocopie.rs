//! MSG_ZEROCOPY (SO_ZEROCOPY, les soldes d'avant 6k) : un programme demande
//! que les pages de son envoi partent sans copie, et apprend par un AVIS dans
//! sa file d'erreurs quand le noyau les a lâchées et qu'il peut réécrire son
//! tampon (`msg_zerocopy_alloc`, `__msg_zerocopy_callback`,
//! net/core/skbuff.c). Chaque envoi de MSG_ZEROCOPY qui part prend un numéro
//! (`sk_zckey`, de 0) ; l'avis dit un intervalle de numéros (ee_info le
//! premier, ee_data le dernier, origine SO_EE_ORIGIN_ZEROCOPY, errno 0), et
//! un avis qui suit celui de la queue de la file s'y fond. TCP et UDP
//! seulement (SO_ZEROCOPY : EOPNOTSUPP ailleurs) ; sans SO_ZEROCOPY, le
//! drapeau est ignoré.
//!
//! Choix de conception (le lot 6 des soldes) : NOUS COPIONS TOUJOURS, et
//! l'avis le dit (SO_EE_CODE_ZEROCOPY_COPIED, ee_code 1). C'est ce que fait
//! Linux quand sa carte ne sait pas lire des pages éparses (sans
//! NETIF_F_SG), et ce qu'il dit sur `lo`, qui copie à l'arrivée (mesuré :
//! COPIED, sauf pour des pages jamais parties, jetées avec les files d'une
//! connexion : rien n'en a été copié chez lui ; chez nous si, à l'envoi, et
//! l'avis le dit) ; le programme sait ainsi que MSG_ZEROCOPY ne lui fait
//! rien gagner ici (la documentation, msg_zerocopy.rst, lui conseille alors
//! d'arrêter). Écarté : épingler vraiment les pages du programme dans les
//! paquets (le vrai zéro-copie) : nos paquets ont un tampon à eux du début à
//! la fin de la pile (paquet.rs), et les cartes de QEMU n'y gagneraient rien.
//!
//! QUAND VIENT L'AVIS : quand Linux lâcherait les pages, pas à la fin de
//! l'envoi (le tampon du programme, copié, est pourtant libre dès là).
//! Écarté, parce qu'un programme le voit : un datagramme bouché (MSG_MORE)
//! n'a d'avis qu'une fois parti (mesuré : la file reste vide d'ici là), et
//! sur `lo` l'avis précède l'erreur ICMP que fait le datagramme (Linux
//! copie les pages à l'entrée de la réception, `skb_orphan_frags_rx`, avant
//! d'y chercher une socket). Donc : UDP, quand la carte a fini le paquet,
//! ou quand il est jeté (l'avis voyage dans son `Proprietaire`, paquet.rs,
//! sur le dernier morceau d'un datagramme fragmenté) ; `lo` le dépose à
//! l'émission, après l'horodatage SND et avant la trame (boucle.rs) : l'ordre
//! de Linux. TCP, quand l'ACK passe le dernier octet de l'envoi, ou quand la
//! connexion jette ses files (tcp.rs, `Partie::avis`) : après l'entrée ACK
//! de SO_TIMESTAMPING, comme chez Linux (`tcp_ack_tstamp` avant de libérer
//! le `sk_buff`).
//!
//! UN AVIS QUI S'ALLONGE (`msg_zerocopy_realloc`) : l'envoi qui s'ajoute au
//! datagramme bouché d'UDP (`allonger`), ou au `sk_buff` de TCP qui attend
//! encore de partir et tient déjà un avis (`suite`, puis `fondre`), ne fait
//! pas d'avis à lui : il allonge celui-là d'un numéro (s'il le suit), qui
//! ne vient qu'une fois tout lâché. Pour TCP, jusqu'à 512 Kio d'envois et
//! 65534 numéros (`byte_limit`, USHRT_MAX - 1), puis un neuf : mesuré, 93
//! envois de 8 Kio vers qui ne lit pas font deux avis, [0, 63] et [64, 92].
//! Écarté : un avis par envoi, fondu seulement dans la file d'erreurs (ce
//! que nous faisions) : un programme qui lit sa file entre deux ACK y voit
//! des avis plus fins et plus tôt, et chaque envoi en attente prend sa part
//! de la mémoire des options (ENOBUFS au 137e, où Linux n'en a qu'un).
//!
//! L'AVIS EST FAIT À L'ENVOI (`preparer`), comme le `sk_buff` que Linux
//! prend alors (`sock_omalloc`) : il ne peut plus se perdre faute de
//! mémoire. Sa place dans la file d'erreurs est gardée d'avance
//! (`Reception::avis_en_vol`). Fini (`finir`), il passe par la file de `lo`
//! de la tâche quand elle est dans le contexte réseau (horodatage.rs dit
//! pourquoi : on y est sous des verrous de la carte ou de TCP, où l'on ne
//! touche à aucune socket), sinon par une chaîne que vide la tâche du
//! réseau (`FINIS`) : l'émission finie d'une carte, un paquet jeté hors du
//! contexte.
//!
//! CE QU'IL COÛTE (mesuré) : rien dans SO_RCVBUF ; 960 octets dans la
//! mémoire des options (SO_MEMINFO, `sk_omem_alloc`), de l'envoi jusqu'à la
//! lecture de son entrée (rendus aussi quand il se fond) ; il n'est fait que
//! si cette mémoire, plus 576 (SKB_TRUESIZE(0)), reste sous `optmem_max`
//! (sinon ENOBUFS : 136 avis en attente) ; et, sans CAP_IPC_LOCK, (taille >>
//! 12) + 2 pages comptées à l'utilisateur sous RLIMIT_MEMLOCK
//! (`mm_account_pinned_pages`, sinon ENOBUFS), rendues avec l'avis. Un envoi
//! qui échoue après l'avoir fait le rend et son numéro avec
//! (`msg_zerocopy_put_abort`) : ni 0 octet, ni EMSGSIZE, ni EFAULT, ni EPIPE
//! ne prennent de numéro (mesuré).

use super::paquet::{self, Paquet};
use super::socket::{self, Socket};
use crate::partage::{Arc, Weak};
use crate::verrou::Verrou;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

/// La mémoire d'un avis dans celle des options : le `truesize` du `sk_buff`
/// vide de `sock_omalloc(sk, 0)` (mesuré, SO_MEMINFO : celui d'une entrée
/// d'horodatage OPT_TSONLY).
pub const MEMOIRE_AVIS: usize = paquet::TAILLE_VIDE;
/// Ce que `sock_omalloc` compte pour décider de le faire (SKB_TRUESIZE(0) :
/// la `sk_buff` et sa `skb_shared_info`, alignées, notre `SURCOUT` ; mesuré :
/// 136 avis passent, 136 × 960 + 576 > 131072).
const MEMOIRE_VERIFIEE: usize = paquet::SURCOUT;
/// Le drapeau d'envoi (`msg_flags`).
pub const MSG_ZEROCOPY: u64 = 0x400_0000;
/// Ce que rend tout refus de faire un avis.
const ENOBUFS: i64 = 105;

/// L'avis d'envois de MSG_ZEROCOPY (le `ubuf_info_msgzc` de Linux) : les
/// numéros `premier` à `premier + nombre - 1`, la taille de leurs envois
/// (`bytelen`), les pages qu'ils comptent à RLIMIT_MEMLOCK, et sa socket (un
/// lien faible : un paquet encore dans la carte ne la fait pas durer,
/// horodatage.rs). `suivant` : sa place dans la chaîne `FINIS` (une chaîne
/// par les avis eux-mêmes : y entrer n'alloue rien).
pub struct Avis {
    socket: Weak<Socket>,
    premier: u32,
    nombre: u32,
    octets: usize,
    pages: u64,
    suivant: Option<Box<Avis>>,
}

/// Les bornes d'un avis de TCP qui s'allonge (`msg_zerocopy_realloc`) : la
/// taille de ses envois (`byte_limit`, « limit to a few TSO ») et son nombre
/// de numéros (USHRT_MAX - 1) ; au-delà, l'envoi en fait un neuf. (Un
/// datagramme bouché d'UDP, de 64 Kio au plus, n'y arrive jamais.)
const OCTETS_MAX: usize = 1 << 19;
const NOMBRE_MAX: u32 = u16::MAX as u32 - 1;

/// Les pages de MSG_ZEROCOPY comptées à l'utilisateur (le `locked_vm` de sa
/// `user_struct`, que lisent `mm_account_pinned_pages` et RLIMIT_MEMLOCK :
/// nos programmes n'ont qu'un utilisateur, comme pour les pages des tubes,
/// tube.rs). Rendues quand l'avis s'en va.
static PAGES: AtomicU64 = AtomicU64::new(0);

/// Les avis finis hors du contexte réseau, que livrera la tâche du réseau
/// (le dernier fini devant).
static FINIS: Verrou<Option<Box<Avis>>> = Verrou::new(None);

impl Drop for Avis {
    fn drop(&mut self) {
        PAGES.fetch_sub(self.pages, Ordering::Relaxed);
    }
}

/// Compte `taille` octets d'envoi aux pages de l'utilisateur
/// (`mm_account_pinned_pages`) : rien pour root (CAP_IPC_LOCK), ni sans
/// limite ; sinon (taille >> 12) + 2 pages, au pire des débordements de
/// page, et ENOBUFS si le total passerait RLIMIT_MEMLOCK. Rend les pages
/// comptées.
fn compter_les_pages(taille: usize) -> Result<u64, i64> {
    if socket::appelant_privilegie() {
        return Ok(0);
    }
    let (limite, _) = crate::processus::avec(|p| p.limite(crate::processus::RLIMIT_MEMLOCK));
    if limite == crate::processus::INFINI {
        return Ok(0);
    }
    let pages = (taille as u64 >> 12) + 2;
    let max = limite >> 12;
    PAGES
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(pages).filter(|&t| t <= max))
        .map(|_| pages)
        .map_err(|_| -ENOBUFS)
}

/// Un envoi de `taille` octets de la socket `s` avec MSG_ZEROCOPY
/// (`msg_zerocopy_alloc`) : sans SO_ZEROCOPY, ou de 0 octet, rien (None :
/// le drapeau est ignoré) ; sinon son avis, de numéro le suivant de la
/// socket. ENOBUFS : la mémoire des options pleine, RLIMIT_MEMLOCK passé,
/// ou plus de mémoire (pour l'avis, ou sa place dans la file d'erreurs).
pub fn preparer(s: &Arc<Socket>, taille: usize) -> Result<Option<Box<Avis>>, i64> {
    if !s.drapeau(socket::ZEROCOPIE) || taille == 0 {
        return Ok(None);
    }
    if s.memoire_des_options() + MEMOIRE_VERIFIEE > socket::OPTMEM_MAX {
        return Err(-ENOBUFS);
    }
    let pages = compter_les_pages(taille)?;
    // Faite avant de prendre le numéro : son échec n'en prend aucun (et ses
    // pages repartent avec elle).
    let mut avis = crate::faillible::boite(Avis { socket: Arc::downgrade(s), premier: 0, nombre: 1, octets: taille, pages, suivant: None })
        .map_err(|_| {
            PAGES.fetch_sub(pages, Ordering::Relaxed);
            -ENOBUFS
        })?;
    {
        let mut r = s.reception.verrouiller();
        let en_vol = r.avis_en_vol + 1;
        if r.erreurs.try_reserve(en_vol).is_err() {
            return Err(-ENOBUFS);
        }
        r.avis_en_vol = en_vol;
    }
    avis.premier = s.cle_zerocopie.fetch_add(1, Ordering::Relaxed);
    s.memoire_avis.fetch_add(MEMOIRE_AVIS, Ordering::Relaxed);
    Ok(Some(avis))
}

/// Un envoi de `taille` octets de MSG_ZEROCOPY s'ajoute au datagramme
/// bouché de la socket `s`, qui a déjà l'avis `avis` (`msg_zerocopy_realloc`
/// sur le `sk_buff` du bouchon) : s'il le suit (son numéro est le prochain
/// de la socket), l'avis s'allonge d'un numéro et de ses pages (au-delà de
/// RLIMIT_MEMLOCK : ENOBUFS), sans mémoire des options de plus ; Ok(false) :
/// il ne le suit pas (un autre envoi a pris un numéro entre-temps), à
/// l'appelant d'en faire un neuf.
pub fn allonger(s: &Socket, avis: &mut Avis, taille: usize) -> Result<bool, i64> {
    if avis.premier.wrapping_add(avis.nombre) != s.cle_zerocopie.load(Ordering::Relaxed) {
        return Ok(false);
    }
    avis.pages += compter_les_pages(taille)?;
    avis.nombre += 1;
    avis.octets += taille;
    s.cle_zerocopie.fetch_add(1, Ordering::Relaxed);
    Ok(true)
}

/// Un envoi de TCP de `taille` octets de la socket `s` avec MSG_ZEROCOPY,
/// quand le `sk_buff` en queue de sa file d'émission, qui attend de partir,
/// tient l'avis `en_queue` (`msg_zerocopy_realloc` : tcp.rs dit quand) : s'il
/// le suit (son numéro est le prochain de la socket) et sous les bornes
/// (`OCTETS_MAX`, `NOMBRE_MAX`), sa suite : son numéro et ses pages (au-delà
/// de RLIMIT_MEMLOCK : ENOBUFS), sans mémoire des options, à fondre dans
/// `en_queue` quand l'envoi aura écrit (`fondre`). Elle est faite en boîte, et
/// sa place dans la file d'erreurs gardée, pour le cas où `en_queue` viendrait
/// avant : l'ACK de ce qu'il tient, pendant que l'envoi attend la place
/// (Linux, lui, le retient par le `sk_buff` de l'envoi). None : un avis neuf
/// (`preparer`).
pub fn suite(s: &Arc<Socket>, en_queue: &Avis, taille: usize) -> Result<Option<Box<Avis>>, i64> {
    if !s.drapeau(socket::ZEROCOPIE)
        || taille == 0
        || en_queue.premier.wrapping_add(en_queue.nombre) != s.cle_zerocopie.load(Ordering::Relaxed)
        || en_queue.nombre >= NOMBRE_MAX
        || en_queue.octets + taille > OCTETS_MAX
    {
        return Ok(None);
    }
    let pages = compter_les_pages(taille)?;
    let mut suite = crate::faillible::boite(Avis { socket: Arc::downgrade(s), premier: 0, nombre: 1, octets: taille, pages, suivant: None })
        .map_err(|_| {
            PAGES.fetch_sub(pages, Ordering::Relaxed);
            -ENOBUFS
        })?;
    {
        let mut r = s.reception.verrouiller();
        let en_vol = r.avis_en_vol + 1;
        if r.erreurs.try_reserve(en_vol).is_err() {
            return Err(-ENOBUFS);
        }
        r.avis_en_vol = en_vol;
    }
    suite.premier = s.cle_zerocopie.fetch_add(1, Ordering::Relaxed);
    Ok(Some(suite))
}

/// L'envoi de la suite `suite` a écrit : elle se fond dans l'avis gardé en
/// queue `en_queue` s'il la précède encore (ses numéros, ses octets, ses
/// pages ; sa place dans la file d'erreurs rendue). Sinon (venu entre-temps,
/// ou un autre envoi passé entre eux), Err : elle devient un avis à elle,
/// compté dans la mémoire des options comme un neuf (sans limite : Linux n'a
/// plus rien à refuser ici), à garder par l'appelant.
pub fn fondre(en_queue: Option<&mut Avis>, mut suite: Box<Avis>) -> Result<(), Box<Avis>> {
    let Some(s) = suite.socket.upgrade() else { return Err(suite) };
    if let Some(q) = en_queue
        && q.premier.wrapping_add(q.nombre) == suite.premier
    {
        q.nombre += suite.nombre;
        q.octets += suite.octets;
        q.pages += core::mem::take(&mut suite.pages);
        let mut r = s.reception.verrouiller();
        r.avis_en_vol = r.avis_en_vol.saturating_sub(1);
        return Ok(());
    }
    s.memoire_avis.fetch_add(MEMOIRE_AVIS, Ordering::Relaxed);
    Err(suite)
}

/// L'envoi de la suite `suite` n'a rien écrit (`msg_zerocopy_put_abort`) :
/// son numéro et sa place rendus, ses pages avec elle.
pub fn annuler_suite(s: &Socket, suite: Box<Avis>) {
    s.cle_zerocopie.fetch_sub(1, Ordering::Relaxed);
    let mut r = s.reception.verrouiller();
    r.avis_en_vol = r.avis_en_vol.saturating_sub(1);
    drop(r);
    drop(suite);
}

/// Ce qu'un ajout au bouchon d'UDP a fait pour son avis (`au_bouchon`).
pub enum AuBouchon {
    Rien,
    Allonge,
    Neuf(Box<Avis>),
}

/// Un envoi de `taille` octets de la socket `s` avec MSG_ZEROCOPY s'ajoute
/// à son datagramme bouché `p` (`msg_zerocopy_realloc` sur le `sk_buff` du
/// bouchon) : il allonge l'avis de `p` s'il le suit, sinon en fait un neuf.
pub fn au_bouchon(s: &Arc<Socket>, p: &mut Paquet, taille: usize) -> Result<AuBouchon, i64> {
    if !s.drapeau(socket::ZEROCOPIE) || taille == 0 {
        return Ok(AuBouchon::Rien);
    }
    if let Some(a) = p.avis_mut()
        && allonger(s, a, taille)?
    {
        return Ok(AuBouchon::Allonge);
    }
    Ok(preparer(s, taille)?.map_or(AuBouchon::Rien, AuBouchon::Neuf))
}

/// L'ajout au bouchon `p` a réussi ou non (`reussi`) : l'avis allongé est
/// raccourci, le neuf annulé, s'il a échoué ; le neuf réussi va au paquet
/// s'il n'en a pas (le `skb_zcopy_set` de `__ip_append_data`), sinon (un
/// autre envoi a pris un numéro entre deux ajouts) il est fini aussitôt :
/// un seul avis par paquet.
pub fn apres_le_bouchon(s: &Socket, p: &mut Paquet, z: AuBouchon, reussi: bool) {
    match z {
        AuBouchon::Rien => {}
        AuBouchon::Allonge => {
            if !reussi && let Some(a) = p.avis_mut() {
                raccourcir(s, a);
            }
        }
        AuBouchon::Neuf(a) if !reussi => annuler(s, a),
        AuBouchon::Neuf(a) if p.avis_mut().is_none() => p.poser_avis(a),
        AuBouchon::Neuf(a) => finir(a),
    }
}

/// L'envoi qui vient d'allonger `avis` a échoué (`msg_zerocopy_put_abort`) :
/// son numéro est rendu (ses pages restent comptées jusqu'à l'avis, comme
/// chez Linux).
pub fn raccourcir(s: &Socket, avis: &mut Avis) {
    avis.nombre -= 1;
    s.cle_zerocopie.fetch_sub(1, Ordering::Relaxed);
}

/// L'envoi de l'avis neuf `avis` a échoué (`msg_zerocopy_put_abort`, puis le
/// rappel d'un avis vide) : son numéro, sa place dans la file d'erreurs, sa
/// mémoire et ses pages sont rendus, sans avis.
pub fn annuler(s: &Socket, avis: Box<Avis>) {
    s.cle_zerocopie.fetch_sub(1, Ordering::Relaxed);
    rendre_la_place(s);
    drop(avis);
}

/// Rend la place et la mémoire d'un avis qui ne sera pas en file.
fn rendre_la_place(s: &Socket) {
    s.memoire_avis.fetch_sub(MEMOIRE_AVIS, Ordering::Relaxed);
    let mut r = s.reception.verrouiller();
    r.avis_en_vol = r.avis_en_vol.saturating_sub(1);
}

/// L'entrée d'un avis vient d'être lue (prendre_en_file, socket.rs) : sa
/// mémoire est rendue (le `consume_skb` d'`ip_recv_error`).
pub fn lu(s: &Socket) {
    s.memoire_avis.fetch_sub(MEMOIRE_AVIS, Ordering::Relaxed);
}

/// Les pages de l'avis ne sont plus tenues (le rappel de Linux) : il part
/// vers la file d'erreurs de sa socket. Dans le contexte réseau, par la
/// file de `lo` de la tâche (vidée en le quittant, après ce qui est déjà
/// dedans) ; sinon, ou cette file pleine, par la tâche du réseau. Sans
/// verrou de socket : on peut être sous celui de la carte ou de TCP.
pub fn finir(avis: Box<Avis>) {
    let avis = if super::contexte::actif() {
        match super::boucle::deposer_avis(avis) {
            Ok(()) => return,
            Err(a) => a,
        }
    } else {
        avis
    };
    plus_tard(avis);
}

/// Confie l'avis à la tâche du réseau (`FINIS`).
pub fn plus_tard(mut avis: Box<Avis>) {
    {
        let mut f = FINIS.verrouiller();
        avis.suivant = f.take();
        *f = Some(avis);
    }
    super::tache::signaler(super::tache::AVIS);
}

/// Met l'avis dans la file d'erreurs de sa socket, si elle vit encore
/// (`__msg_zerocopy_callback` : fondu dans la queue s'il la prolonge, ou
/// une entrée neuve, COPIED ; puis le réveil). Sans verrou tenu (la file de
/// `lo`, la tâche du réseau).
pub fn livrer(avis: Box<Avis>) {
    let Some(s) = avis.socket.upgrade() else { return };
    if !s.mettre_avis_en_file(avis.premier, avis.nombre) {
        // Fondu dans l'entrée d'avant : sa mémoire est rendue (`consume_skb`).
        s.memoire_avis.fetch_sub(MEMOIRE_AVIS, Ordering::Relaxed);
    }
}

/// Livre les avis finis hors du contexte réseau, dans l'ordre où ils l'ont
/// été (la tâche du réseau, bit AVIS).
pub fn livrer_les_finis() {
    let mut chaine = FINIS.verrouiller().take();
    // La chaîne est à l'envers (le dernier devant) : retournée.
    let mut dans_l_ordre: Option<Box<Avis>> = None;
    while let Some(mut a) = chaine {
        chaine = a.suivant.take();
        a.suivant = dans_l_ordre;
        dans_l_ordre = Some(a);
    }
    while let Some(mut a) = dans_l_ordre {
        dans_l_ordre = a.suivant.take();
        livrer(a);
    }
}
