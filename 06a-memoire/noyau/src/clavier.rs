//! Le clavier PS/2, derrière le contrôleur 8042.
//!
//! Le clavier ne parle pas au processeur directement : il envoie, sur un
//! fil série, des « codes de balayage » (scancodes) au contrôleur 8042 de
//! la carte mère, qui les range dans un registre (port 0x60) et lève
//! l'IRQ 1. Le code dit QUELLE TOUCHE a bougé, pas quel caractère : la
//! touche à droite de Tab envoie toujours 0x10, qu'il y ait « A » (AZERTY)
//! ou « Q » (QWERTY) dessus. Le choix du caractère est fait ici, par le
//! noyau, avec une table de disposition, comme les « keymaps » de Linux.
//!
//! Chaque touche envoie un code quand on l'enfonce (make), et le même avec
//! le bit 7 à 1 quand on la relâche (break) : 0x10 puis 0x90. Les touches
//! ajoutées après le clavier d'origine (flèches, AltGr, Ctrl droit...)
//! sont précédées de 0xE0.
//!
//! Le travail est coupé en deux, comme dans Linux :
//!   - le gestionnaire d'IRQ, interruptions coupées, ne fait que lire
//!     l'octet du 8042 et le ranger dans une file ;
//!   - le noyau, plus tard, interruptions actives, vide la file, suit
//!     l'état des touches de modification (Maj, AltGr...) et traduit en
//!     caractères.
//! Une interruption doit rendre la main vite : si on tardait, le 8042 ne
//! pourrait pas nous donner l'octet suivant.
//!
//! Sur un PC récent sans prise PS/2, le BIOS émule ce même 8042 pour un
//! clavier USB (« USB legacy support ») : ce pilote y fonctionne aussi, en
//! démarrage BIOS. Un vrai pilote USB (contrôleur xHCI) viendra bien plus
//! tard.

use crate::pic;
use crate::port;
use crate::verrou::Verrou;

pub const IRQ: u8 = 1;

const DONNEES: u16 = 0x60;
/// En lecture : registre d'état ; en écriture : commandes au 8042.
const ETAT_COMMANDE: u16 = 0x64;
/// Bit d'état : un octet attend d'être lu sur le port 0x60.
const SORTIE_PLEINE: u8 = 1 << 0;
/// Bit d'état : le 8042 n'a pas encore pris notre dernier octet.
const ENTREE_PLEINE: u8 = 1 << 1;

// ---------------------------------------------------------------------------
// Le contrôleur 8042
// ---------------------------------------------------------------------------

/// Attend qu'un bit du registre d'état prenne la valeur voulue. Avec une
/// limite : sur une machine sans 8042, on ne doit pas boucler pour
/// toujours (Linux : i8042_wait_read, même principe).
fn attendre_etat(bit: u8, voulu: bool) -> Result<(), ()> {
    for _ in 0..100_000 {
        // SAFETY : lecture du registre d'état, sans effet.
        if (unsafe { port::lire(ETAT_COMMANDE) } & bit != 0) == voulu {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(())
}

fn commande(octet: u8) -> Result<(), ()> {
    attendre_etat(ENTREE_PLEINE, false)?;
    // SAFETY : commande documentée du 8042, sur son port de commande.
    unsafe { port::ecrire(ETAT_COMMANDE, octet) };
    Ok(())
}

fn ecrire_donnee(octet: u8) -> Result<(), ()> {
    attendre_etat(ENTREE_PLEINE, false)?;
    // SAFETY : réponse à une commande qui attend un octet de données.
    unsafe { port::ecrire(DONNEES, octet) };
    Ok(())
}

fn lire_donnee() -> Result<u8, ()> {
    attendre_etat(SORTIE_PLEINE, true)?;
    // SAFETY : un octet est disponible (bit SORTIE_PLEINE).
    Ok(unsafe { port::lire(DONNEES) })
}

/// Octet de configuration du 8042 (CCB, « Controller Configuration Byte »).
const CCB_IRQ_CLAVIER: u8 = 1 << 0;
const CCB_HORLOGE_CLAVIER_COUPEE: u8 = 1 << 4;
const CCB_TRADUCTION: u8 = 1 << 6;

/// Met le 8042 dans l'état qu'on attend, sans supposer ce que le BIOS a
/// laissé : IRQ 1 activée, clavier actif, traduction en jeu 1.
///
/// Les jeux de codes : les claviers modernes parlent le « jeu 2 », mais le
/// 8042 sait le traduire en « jeu 1 », celui du clavier du PC XT de 1981.
/// Le BIOS active cette traduction, et toute la documentation du PC la
/// suppose : on la garde. Option écartée : couper la traduction et lire
/// le jeu 2 directement. Ce n'est pas plus juste (Linux garde aussi la
/// traduction par défaut), et certains claviers émulés la gèrent mal.
///
/// Option écartée aussi : la réinitialisation complète du 8042 et le test
/// de chaque port, comme le fait Linux (i8042.c). Utile quand le BIOS a
/// mal fait son travail ; on l'ajoutera si on rencontre une telle machine.
pub fn initialiser() -> Result<(), ()> {
    // Faire taire le clavier pendant la configuration (commande 0xAD),
    // comme Linux : sinon, une touche tapée maintenant arriverait sur le
    // port 0x60 et serait lue à la place de l'octet de configuration.
    commande(0xAD)?;

    // Vider ce que le 8042 aurait gardé (touches tapées pendant le
    // démarrage) : sinon il attendrait qu'on le lise pour lever l'IRQ.
    // SAFETY : lectures du port de données tant qu'il a quelque chose.
    while unsafe { port::lire(ETAT_COMMANDE) } & SORTIE_PLEINE != 0 {
        unsafe { port::lire(DONNEES) };
    }

    // Lire l'octet de configuration (commande 0x20), le modifier, le
    // réécrire (commande 0x60). On ne touche pas aux bits de la souris.
    commande(0x20)?;
    let mut ccb = lire_donnee()?;
    ccb |= CCB_IRQ_CLAVIER | CCB_TRADUCTION;
    ccb &= !CCB_HORLOGE_CLAVIER_COUPEE;
    commande(0x60)?;
    ecrire_donnee(ccb)?;
    commande(0xAE)?; // Le clavier peut reparler.

    pic::demasquer(IRQ);
    Ok(())
}

// ---------------------------------------------------------------------------
// La file entre le gestionnaire d'IRQ et le reste du noyau
// ---------------------------------------------------------------------------

/// Une file circulaire d'octets : on écrit à `fin`, on lit à `debut`, et
/// les deux indices font le tour du tableau. 64 codes, c'est plus qu'on ne
/// peut taper entre deux passages du noyau. Si elle est pleine, on perd
/// les nouveaux codes plutôt que d'écraser les anciens.
///
/// Sous Verrou, qui coupe les interruptions : le noyau qui lit ne peut pas
/// être interrompu par l'IRQ qui écrit au milieu de sa lecture. Option
/// écartée : une file sans verrou, à indices atomiques (kfifo de Linux,
/// possible avec un seul écrivain et un seul lecteur). Plus rapide, mais
/// bien plus délicate à prouver juste ; pour un clavier, rien ne presse.
struct File {
    octets: [u8; 64],
    debut: usize,
    nombre: usize,
}

impl File {
    fn ajouter(&mut self, octet: u8) {
        if self.nombre < self.octets.len() {
            let fin = (self.debut + self.nombre) % self.octets.len();
            self.octets[fin] = octet;
            self.nombre += 1;
        }
    }

    fn retirer(&mut self) -> Option<u8> {
        if self.nombre == 0 {
            return None;
        }
        let octet = self.octets[self.debut];
        self.debut = (self.debut + 1) % self.octets.len();
        self.nombre -= 1;
        Some(octet)
    }
}

static FILE: Verrou<File> = Verrou::new(File { octets: [0; 64], debut: 0, nombre: 0 });

/// Le gestionnaire de l'IRQ 1 : lire l'octet, le ranger, c'est tout.
/// Il FAUT le lire : tant que le port 0x60 est plein, le 8042 n'envoie
/// plus rien, et le clavier semblerait mort.
pub fn interruption() {
    // SAFETY : l'IRQ 1 signifie qu'un octet attend sur le port 0x60.
    let code = unsafe { port::lire(DONNEES) };
    FILE.verrouiller().ajouter(code);
}

// ---------------------------------------------------------------------------
// Des codes aux caractères
// ---------------------------------------------------------------------------

/// Une disposition : pour chaque code (sans 0xE0), le caractère obtenu
/// seul, avec Maj, avec AltGr. '\0' = rien.
type Disposition = [[char; 3]; 0x59];

/// La disposition utilisée. AZERTY français par défaut ; pour un clavier
/// américain, remplacer par &QWERTY. (Linux la choisit au démarrage avec
/// loadkeys ; on y viendra avec un système de fichiers.)
static DISPOSITION: &Disposition = &AZERTY;

/// Les codes de jeu 1 sont ceux du clavier du PC XT : la place de chaque
/// touche, numérotée de gauche à droite et de haut en bas.
/// Pas de touches mortes (^ puis e = ê) : ^ et ¨ s'affichent tels quels.
const AZERTY: Disposition = {
    let mut t = [['\0'; 3]; 0x59];
    t[0x02] = ['&', '1', '\0'];
    t[0x03] = ['é', '2', '~'];
    t[0x04] = ['"', '3', '#'];
    t[0x05] = ['\'', '4', '{'];
    t[0x06] = ['(', '5', '['];
    t[0x07] = ['-', '6', '|'];
    t[0x08] = ['è', '7', '`'];
    t[0x09] = ['_', '8', '\\'];
    t[0x0A] = ['ç', '9', '^'];
    t[0x0B] = ['à', '0', '@'];
    t[0x0C] = [')', '°', ']'];
    t[0x0D] = ['=', '+', '}'];
    t[0x10] = ['a', 'A', '\0'];
    t[0x11] = ['z', 'Z', '\0'];
    t[0x12] = ['e', 'E', '€'];
    t[0x13] = ['r', 'R', '\0'];
    t[0x14] = ['t', 'T', '\0'];
    t[0x15] = ['y', 'Y', '\0'];
    t[0x16] = ['u', 'U', '\0'];
    t[0x17] = ['i', 'I', '\0'];
    t[0x18] = ['o', 'O', '\0'];
    t[0x19] = ['p', 'P', '\0'];
    t[0x1A] = ['^', '¨', '\0'];
    t[0x1B] = ['$', '£', '¤'];
    t[0x1E] = ['q', 'Q', '\0'];
    t[0x1F] = ['s', 'S', '\0'];
    t[0x20] = ['d', 'D', '\0'];
    t[0x21] = ['f', 'F', '\0'];
    t[0x22] = ['g', 'G', '\0'];
    t[0x23] = ['h', 'H', '\0'];
    t[0x24] = ['j', 'J', '\0'];
    t[0x25] = ['k', 'K', '\0'];
    t[0x26] = ['l', 'L', '\0'];
    t[0x27] = ['m', 'M', '\0'];
    t[0x28] = ['ù', '%', '\0'];
    t[0x29] = ['²', '\0', '\0'];
    t[0x2B] = ['*', 'µ', '\0'];
    t[0x2C] = ['w', 'W', '\0'];
    t[0x2D] = ['x', 'X', '\0'];
    t[0x2E] = ['c', 'C', '\0'];
    t[0x2F] = ['v', 'V', '\0'];
    t[0x30] = ['b', 'B', '\0'];
    t[0x31] = ['n', 'N', '\0'];
    t[0x32] = [',', '?', '\0'];
    t[0x33] = [';', '.', '\0'];
    t[0x34] = [':', '/', '\0'];
    t[0x35] = ['!', '§', '\0'];
    // La touche en plus des claviers européens, à gauche de W.
    t[0x56] = ['<', '>', '\0'];
    communes(t)
};

#[allow(dead_code)] // Disposition de rechange, voir DISPOSITION.
const QWERTY: Disposition = {
    let mut t = [['\0'; 3]; 0x59];
    let lignes: [(usize, &[u8], &[u8]); 4] = [
        (0x02, b"1234567890-=", b"!@#$%^&*()_+"),
        (0x10, b"qwertyuiop[]", b"QWERTYUIOP{}"),
        (0x1E, b"asdfghjkl;'`", b"ASDFGHJKL:\"~"),
        (0x2B, b"\\zxcvbnm,./", b"|ZXCVBNM<>?"),
    ];
    let mut l = 0;
    while l < lignes.len() {
        let (premier, seul, maj) = lignes[l];
        let mut i = 0;
        while i < seul.len() {
            t[premier + i] = [seul[i] as char, maj[i] as char, '\0'];
            i += 1;
        }
        l += 1;
    }
    communes(t)
};

/// Les touches qui ne dépendent pas de la disposition.
const fn communes(mut t: Disposition) -> Disposition {
    t[0x0E] = ['\u{8}', '\u{8}', '\0']; // Retour arrière
    t[0x0F] = ['\t', '\t', '\0'];
    t[0x1C] = ['\n', '\n', '\0'];       // Entrée
    t[0x39] = [' ', ' ', '\0'];
    // Pavé numérique, chiffres toujours (on ne suit pas encore Verr Num).
    let pave = *b"789-456+1230.";
    let mut i = 0;
    while i < pave.len() {
        t[0x47 + i] = [pave[i] as char, pave[i] as char, '\0'];
        i += 1;
    }
    t[0x37] = ['*', '*', '\0'];
    t
}

/// Ce qu'on sait des touches de modification, mis à jour à chaque code.
struct Decodeur {
    /// Le code précédent était 0xE0 : celui-ci est une touche « étendue ».
    etendu: bool,
    /// Codes encore à ignorer, après 0xE1 (touche Pause).
    a_ignorer: u8,
    maj_gauche: bool,
    maj_droite: bool,
    altgr: bool,
    verr_maj: bool,
}

static DECODEUR: Verrou<Decodeur> = Verrou::new(Decodeur {
    etendu: false, a_ignorer: 0,
    maj_gauche: false, maj_droite: false, altgr: false, verr_maj: false,
});

impl Decodeur {
    /// Traite un code ; rend le caractère produit, s'il y en a un.
    fn traiter(&mut self, code: u8) -> Option<char> {
        if self.a_ignorer > 0 {
            self.a_ignorer -= 1;
            return None;
        }
        match code {
            0xE0 => { self.etendu = true; return None; }
            // Pause envoie E1 1D 45 E1 9D C5, sans code de relâchement.
            0xE1 => { self.a_ignorer = 5; return None; }
            _ => {}
        }
        let etendu = core::mem::replace(&mut self.etendu, false);
        let enfoncee = code & 0x80 == 0;
        let touche = code & 0x7F;

        match (etendu, touche) {
            (false, 0x2A) => self.maj_gauche = enfoncee,
            (false, 0x36) => self.maj_droite = enfoncee,
            (true, 0x38) => self.altgr = enfoncee, // Alt de droite = AltGr.
            (false, 0x3A) if enfoncee => self.verr_maj = !self.verr_maj,
            // Entrée et / du pavé numérique.
            (true, 0x1C) if enfoncee => return Some('\n'),
            (true, 0x35) if enfoncee => return Some('/'),
            // Les autres touches étendues (flèches, Inser, Ctrl droit...)
            // et les relâchements ne produisent pas de caractère.
            (false, _) if enfoncee => return self.caractere(touche),
            _ => {}
        }
        None
    }

    fn caractere(&self, touche: u8) -> Option<char> {
        let [seul, maj, altgr] = *DISPOSITION.get(touche as usize)?;
        let mut majuscule = self.maj_gauche || self.maj_droite;
        // Verr Maj n'agit que sur les lettres, et Maj l'annule. Les lettres
        // ASCII seulement : sur la touche é, Maj donne 2, pas É (que la
        // disposition ne connaît pas), et Verr Maj + é doit rester é.
        if self.verr_maj && seul.is_ascii_alphabetic() {
            majuscule = !majuscule;
        }
        let c = if self.altgr { altgr } else if majuscule { maj } else { seul };
        if c == '\0' { None } else { Some(c) }
    }
}

/// Le prochain caractère tapé, s'il y en a un. À appeler hors interruption.
pub fn lire_caractere() -> Option<char> {
    loop {
        let code = FILE.verrouiller().retirer()?;
        if let Some(c) = DECODEUR.verrouiller().traiter(code) {
            return Some(c);
        }
    }
}

/// Y a-t-il des codes en attente ? Pour décider de dormir ou non.
pub fn en_attente() -> bool {
    FILE.verrouiller().nombre > 0
}
