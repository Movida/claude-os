//! Les lignes de /etc/demarrage : ce que le noyau lance au démarrage.
//!
//! Sans `fork` ni `execve` (6l), aucun programme ne peut en lancer un autre :
//! le noyau joue le rôle d'`init`, et lit dans un fichier ce qu'il doit
//! lancer, une commande par ligne, dans l'ordre (un petit `inittab`).
//! Pourquoi un fichier de l'archive plutôt que la liste des fichiers de
//! /bin (ce que faisait 6b), une liste dans le noyau, ou sa ligne de
//! commande (le `init=` de Linux) : il faut des arguments et un
//! environnement par programme (`claude --version` en 6d,
//! `DISABLE_AUTOUPDATER=1 claude -p "bonjour"` en 6i) ; la ligne de
//! commande du noyau ne lance qu'un programme, et notre chargeur n'en a
//! pas ; un fichier se change sans reconstruire le noyau, et chaque archive
//! a le sien (`make`, `make tests-qemu`, `make trace`).
//!
//! La syntaxe est un SOUS-ENSEMBLE STRICT de celle du `sh` de POSIX (dash,
//! le `/bin/sh` d'Ubuntu) : tout ce que cette fonction accepte, il le
//! découpe et le lance de la même façon (les tests le vérifient avec le
//! `sh` de la machine, et un relecteur l'a fait sur 300 000 lignes tirées
//! au hasard). En 6l, le même fichier pourra donc être lancé tel quel par
//! un shell, comme un `/etc/rc`. (bash, lui, diffère sur deux points :
//! `_=x` en tête, qu'il remplace par le chemin du programme, et `A+=x`,
//! une affectation par ajout ; chez nous, `_=x` est une affectation comme
//! pour dash, et `A+=x` un programme sans chemin absolu, refusé.)
//!   - des mots séparés par des espaces ou des tabulations ;
//!   - des guillemets simples (tout est littéral jusqu'au suivant) ou
//!     doubles (sans `$`, `` ` `` ni `\`, que `sh` y interprète :
//!     refusés), collés ou non au reste du mot (`a"b c"d` est un seul mot,
//!     `""` un mot vide) ;
//!   - hors des guillemets, seulement des caractères que `sh` laisse tels
//!     quels (lettres, chiffres, `_ - . / , : + = @ %`, et `#` ailleurs qu'en
//!     tête de mot) ; tout autre caractère qu'un shell interpréterait (`$`,
//!     `*`, `;`, `|`, `~`...) est refusé plutôt que pris au pied de la
//!     lettre ;
//!   - `#` en tête de mot commence un commentaire, jusqu'à la fin de la
//!     ligne ;
//!   - des affectations `NOM=valeur` en tête (NOM : une lettre ou `_`, puis
//!     lettres, chiffres et `_`, sans guillemets avant le `=`, comme pour
//!     `sh`) ajoutent une variable à l'environnement du programme, ou
//!     remplacent celle du noyau ;
//!   - LES SEULES ENTORSES à `sh` : des options `--dir=CHEMIN`, entre les
//!     affectations et le programme, donnent un dossier pré-ouvert à un
//!     programme WebAssembly (comme `wasmtime --dir`), et des options
//!     `--tcplisten=ADRESSE:PORT` (6h) une écoute TCP pré-ouverte (comme
//!     le `--tcplisten` de wasmtime, qu'il écrit maintenant
//!     `-S tcplisten=`) : l'adresse d'IPv4 en chiffres, et le port ;
//!   - puis le programme, par son CHEMIN ABSOLU (qui devient aussi
//!     argv[0]), et ses arguments. Un mot qui commence par `/` n'est ni un
//!     mot réservé de sh (`if`, `while`...), ni une commande interne
//!     (`exec`, `.`, `:`), ni un alias : c'est ce qui rend la promesse vraie
//!     pour toute la ligne. Et le noyau n'a pas de `PATH` à chercher ;
//!   - depuis 6e, `&` à la fin de la ligne (collé ou non au dernier mot,
//!     avant un commentaire éventuel) : la commande est lancée « en
//!     arrière-plan », sans l'attendre, comme le fait `sh` ; rien d'autre
//!     ne peut suivre (`a & b`, deux commandes, et `&&` sont refusés) ;
//!   - et la commande interne `wait`, seule sur sa ligne, sans guillemets
//!     ni arguments : elle attend toutes les commandes lancées par `&` ;
//!   - depuis 6i, des redirections d'entrée, n'importe où dans la commande
//!     (avant le programme comme après) : `< CHEMIN` donne le fichier pour
//!     entrée standard (le descripteur 0), `N< CHEMIN` pour le descripteur
//!     N. Comme pour `dash` : N est UN chiffre, collé au `<` et en tête de
//!     son mot (`3<f` : le descripteur 3 ; `3 <f`, `a3<f`, `'3'<f`, `10<f` :
//!     un argument, puis l'entrée standard) ; `<` finit un mot, comme `&` ;
//!     le chemin suit, collé ou non, avec les mêmes guillemets qu'un mot,
//!     mais jamais un commentaire. `<<`, `<>`, `<&`, `<|`, `<(` (d'autres
//!     redirections de sh) et `>` sont refusés ; les fichiers s'ouvrent de
//!     gauche à droite (`< a < b` : a, puis b), et une redirection laisse les
//!     mots suivants en tête (`<f A=1 /bin/x` : A=1 est une affectation).
//!     Pour `claude -p < /dev/null` (sinon il attend 3 s son entrée), et le
//!     jeton de l'abonnement, donné par un descripteur (6i) ;
//!   - depuis 6i, la commande interne `cd CHEMIN`, seule sur sa ligne, avec
//!     un chemin absolu (entre guillemets s'il le faut) : le dossier courant
//!     des commandes suivantes. Comme `cd` de dash (son -L par défaut), le
//!     chemin est d'abord ramené à sa forme simple (`/a/./b/../c//` :
//!     `/a/c`), sans regarder les liens, et c'est lui que reçoit la variable
//!     PWD des programmes.
//! Pas de `\` en fin de ligne, pas de variables, pas d'échappements : ce
//! n'est pas un shell, seulement de quoi écrire une commande.
//!
//! Comme le reste de la bibliothèque, sans `alloc` : les mots sont écrits,
//! guillemets retirés, dans un tampon que donne l'appelant (deux fois la
//! longueur de la ligne, plus deux octets, suffisent toujours).

use core::fmt;

/// Pourquoi une ligne est refusée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Un guillemet simple ou double jamais refermé.
    GuillemetNonFerme,
    /// Un caractère que `sh` interpréterait, hors des guillemets (ou `$`,
    /// `` ` ``, `\` entre guillemets doubles), ou un octet de contrôle.
    Caractere(u8),
    /// Une option `--dir=` sans chemin.
    DossierVide,
    /// Une option `--tcplisten=` dont la valeur n'est pas ADRESSE:PORT
    /// (l'adresse d'IPv4 en chiffres).
    Ecoute,
    /// Des affectations ou des options, mais pas de programme.
    SansProgramme,
    /// Le programme n'est pas un chemin absolu.
    CheminRelatif,
    /// Le tampon de l'appelant est trop petit (voir `taille_tampon`).
    TamponTropPetit,
    /// Quelque chose suit `&`.
    ApresEsperluette,
    /// `wait` avec des arguments, des affectations ou `&`.
    Attendre,
    /// Un `<` sans chemin après lui (la fin de la ligne, ou un
    /// commentaire).
    RedirectionSansChemin,
    /// `cd` sans un seul chemin absolu, ou avec des affectations ou `&`.
    Cd,
}

// Affichés par le noyau : sans accents.
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Erreur::GuillemetNonFerme => f.write_str("guillemet non ferme"),
            Erreur::Caractere(c) if c.is_ascii_graphic() => write!(f, "caractere special '{}' hors des guillemets", *c as char),
            Erreur::Caractere(c) => write!(f, "octet {c:#04x} interdit"),
            Erreur::DossierVide => f.write_str("--dir= sans chemin"),
            Erreur::Ecoute => f.write_str("--tcplisten= attend ADRESSE:PORT (IPv4, en chiffres)"),
            Erreur::SansProgramme => f.write_str("pas de programme a lancer"),
            Erreur::CheminRelatif => f.write_str("le programme doit etre donne par son chemin absolu"),
            Erreur::TamponTropPetit => f.write_str("ligne trop longue"),
            Erreur::ApresEsperluette => f.write_str("rien ne peut suivre &"),
            Erreur::Attendre => f.write_str("wait s'emploie seul"),
            Erreur::RedirectionSansChemin => f.write_str("< sans chemin"),
            Erreur::Cd => f.write_str("cd s'emploie seul, avec un chemin absolu"),
        }
    }
}

/// Les lignes d'un fichier, numérotées à partir de 1, sans leur fin de
/// ligne. Un fichier qui ne finit pas par une fin de ligne a quand même sa
/// dernière ligne.
pub fn lignes(texte: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let vide = texte.is_empty();
    let texte = texte.strip_suffix(b"\n").unwrap_or(texte);
    texte.split(|&o| o == b'\n').enumerate().map(|(i, l)| (i + 1, l)).filter(move |_| !vide)
}

/// La taille de tampon qui suffit toujours pour découper `ligne` : chaque
/// mot y prend son genre, ses octets et un zéro final, et il y a au plus un
/// mot pour deux octets de la ligne.
pub fn taille_tampon(ligne: &[u8]) -> usize {
    2 * ligne.len() + 2
}

/// Ce qu'est un mot de la ligne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Genre {
    /// `NOM=valeur`, en tête de ligne.
    Affectation,
    /// `--dir=CHEMIN` : les octets du mot sont le chemin.
    Dossier,
    /// `--tcplisten=ADRESSE:PORT` : les octets du mot sont l'adresse et le
    /// port, vérifiés.
    Ecoute,
    /// Le programme, ou l'un de ses arguments.
    Argument,
    /// `N< CHEMIN` : le premier octet du mot est le numéro du descripteur,
    /// en chiffre ASCII (« 0 » à « 9 »), les suivants le chemin.
    Redirection,
}

/// Ce que dit une ligne qui n'est pas vide.
#[derive(Debug, Clone, Copy)]
pub enum Ligne<'t> {
    /// Une commande à lancer.
    Commande(Commande<'t>),
    /// `wait` : attendre les commandes lancées par `&`.
    Attendre,
    /// `cd CHEMIN` : le dossier courant des commandes suivantes, son chemin
    /// absolu ramené à sa forme simple.
    Dossier(&'t [u8]),
}

/// Une ligne découpée : ses mots, guillemets retirés, dans le tampon de
/// l'appelant, et si elle se lance en arrière-plan (`&`).
#[derive(Debug, Clone, Copy)]
pub struct Commande<'t> {
    tampon: &'t [u8],
    arriere_plan: bool,
}

impl<'t> Commande<'t> {
    /// Les mots, dans l'ordre, avec leur genre. Aucun ne contient d'octet
    /// nul.
    fn mots(&self) -> impl Iterator<Item = (Genre, &'t [u8])> + 't {
        let mut reste = self.tampon;
        core::iter::from_fn(move || {
            let (&genre, suite) = reste.split_first()?;
            let fin = suite.iter().position(|&o| o == 0)?;
            let mot = &suite[..fin];
            reste = &suite[fin + 1..];
            let genre = match genre {
                b'a' => Genre::Affectation,
                b'd' => Genre::Dossier,
                b'e' => Genre::Ecoute,
                b'r' => Genre::Redirection,
                _ => Genre::Argument,
            };
            Some((genre, mot))
        })
    }

    /// Les affectations `NOM=valeur`, telles quelles.
    pub fn affectations(&self) -> impl Iterator<Item = &'t [u8]> + 't {
        self.mots().filter(|(g, _)| *g == Genre::Affectation).map(|(_, m)| m)
    }

    /// Les chemins des options `--dir=`.
    pub fn dossiers(&self) -> impl Iterator<Item = &'t [u8]> + 't {
        self.mots().filter(|(g, _)| *g == Genre::Dossier).map(|(_, m)| m)
    }

    /// Les écoutes des options `--tcplisten=` : l'adresse et le port de
    /// chacune (vérifiés par `decouper`), et le mot tel qu'écrit, pour les
    /// messages.
    pub fn ecoutes(&self) -> impl Iterator<Item = ([u8; 4], u16, &'t [u8])> + 't {
        self.mots().filter(|(g, _)| *g == Genre::Ecoute).filter_map(|(_, m)| adresse_et_port(m).map(|(a, p)| (a, p, m)))
    }

    /// Les redirections, dans l'ordre de la ligne (celui où les ouvrir) :
    /// le descripteur, et le chemin.
    pub fn redirections(&self) -> impl Iterator<Item = (u8, &'t [u8])> + 't {
        self.mots().filter(|(g, _)| *g == Genre::Redirection).filter_map(|(_, m)| m.split_first().map(|(&n, c)| (n - b'0', c)))
    }

    /// Le programme puis ses arguments : argv.
    pub fn arguments(&self) -> impl Iterator<Item = &'t [u8]> + 't {
        self.mots().filter(|(g, _)| *g == Genre::Argument).map(|(_, m)| m)
    }

    /// Le programme : le premier argument (toujours là, et un chemin
    /// absolu : vérifié).
    pub fn programme(&self) -> &'t [u8] {
        self.arguments().next().unwrap_or(&[])
    }

    /// La ligne finit-elle par `&` (lancer sans attendre) ?
    pub fn arriere_plan(&self) -> bool {
        self.arriere_plan
    }
}

/// Un caractère que `sh` laisse tel quel hors des guillemets. (Les octets
/// de 0x80 et plus, l'UTF-8, aussi : `sh` ne les interprète pas.)
fn ordinaire(o: u8) -> bool {
    o.is_ascii_alphanumeric() || b"_-./,:+=@%#".contains(&o) || o >= 0x80
}

/// `ADRESSE:PORT` : quatre nombres décimaux de 0 à 255 séparés par des
/// points, sans zéro en tête (« 010 » serait de l'octal pour inet_aton : on
/// refuse plutôt que de deviner, comme inet_pton et le Rust de wasmtime),
/// puis un port de 0 à 65535. Pas de nom de machine : le noyau ne résout
/// pas de noms (wasmtime, si : il passe par le DNS de son hôte), et pas
/// d'IPv6, que nous n'avons pas.
pub fn adresse_et_port(texte: &[u8]) -> Option<([u8; 4], u16)> {
    let deux_points = texte.iter().rposition(|&o| o == b':')?;
    let (adresse, port) = (&texte[..deux_points], &texte[deux_points + 1..]);
    // Un nombre décimal d'au plus `chiffres` chiffres, sans zéro en tête.
    let nombre = |t: &[u8], chiffres: usize| -> Option<u32> {
        if t.is_empty() || t.len() > chiffres || !t.iter().all(u8::is_ascii_digit) || (t.len() > 1 && t[0] == b'0') {
            return None;
        }
        Some(t.iter().fold(0, |n, &c| n * 10 + (c - b'0') as u32))
    };
    let mut octets = [0u8; 4];
    let mut parties = adresse.split(|&o| o == b'.');
    for o in &mut octets {
        *o = u8::try_from(nombre(parties.next()?, 3)?).ok()?;
    }
    if parties.next().is_some() {
        return None;
    }
    Some((octets, u16::try_from(nombre(port, 5)?).ok()?))
}

/// `mot` (brut, avec ses guillemets) commence-t-il par `NOM=`, sans
/// guillemet avant le `=` ? C'est la règle de `sh` pour une affectation.
fn est_affectation(brut: &[u8]) -> bool {
    let Some(egal) = brut.iter().position(|&o| o == b'=') else { return false };
    let nom = &brut[..egal];
    !nom.is_empty()
        && (nom[0].is_ascii_alphabetic() || nom[0] == b'_')
        && nom.iter().all(|&o| o.is_ascii_alphanumeric() || o == b'_')
}

/// Lit un mot brut de `ligne` à partir de `i`, jusqu'au prochain blanc hors
/// des guillemets, ou un `&` ou un `<` (des opérateurs pour sh, même collés
/// au mot) ; l'écrit, guillemets retirés, dans `tampon` à partir de
/// `ecrit`. `i` et `ecrit` avancent d'autant.
fn lire_mot(ligne: &[u8], i: &mut usize, tampon: &mut [u8], ecrit: &mut usize) -> Result<(), Erreur> {
    while *i < ligne.len() && ligne[*i] != b' ' && ligne[*i] != b'\t' && ligne[*i] != b'&' && ligne[*i] != b'<' {
        match ligne[*i] {
            b'\'' => {
                let fin = ligne[*i + 1..].iter().position(|&o| o == b'\'').ok_or(Erreur::GuillemetNonFerme)?;
                for &o in &ligne[*i + 1..*i + 1 + fin] {
                    if o == 0 || o == b'\n' {
                        return Err(Erreur::Caractere(o));
                    }
                    tampon[*ecrit] = o;
                    *ecrit += 1;
                }
                *i += fin + 2;
            }
            b'"' => {
                let fin = ligne[*i + 1..].iter().position(|&o| o == b'"').ok_or(Erreur::GuillemetNonFerme)?;
                for &o in &ligne[*i + 1..*i + 1 + fin] {
                    if o == b'$' || o == b'`' || o == b'\\' || o == 0 || o == b'\n' {
                        return Err(Erreur::Caractere(o));
                    }
                    tampon[*ecrit] = o;
                    *ecrit += 1;
                }
                *i += fin + 2;
            }
            o if ordinaire(o) => {
                tampon[*ecrit] = o;
                *ecrit += 1;
                *i += 1;
            }
            o => return Err(Erreur::Caractere(o)),
        }
    }
    Ok(())
}

/// `cd CHEMIN`, puis peut-être un commentaire : le chemin, un seul mot
/// absolu (ses guillemets compris : un `#` y est un caractère, comme collé
/// à un mot), ramené à sa forme simple dans `tampon`.
fn dossier<'t>(ligne: &[u8], tampon: &'t mut [u8]) -> Result<&'t [u8], Erreur> {
    let mut i = ligne.iter().position(|&o| o != b' ' && o != b'\t').unwrap_or(0) + 2;
    while i < ligne.len() && (ligne[i] == b' ' || ligne[i] == b'\t') {
        i += 1;
    }
    let mut ecrit = 0;
    if i < ligne.len() && ligne[i] != b'#' {
        lire_mot(ligne, &mut i, tampon, &mut ecrit)?;
    }
    while i < ligne.len() && (ligne[i] == b' ' || ligne[i] == b'\t') {
        i += 1;
    }
    let commentaire = i < ligne.len() && ligne[i] == b'#';
    if (i < ligne.len() && !commentaire) || ecrit == 0 || tampon[0] != b'/' {
        return Err(Erreur::Cd);
    }
    let n = forme_simple(&mut tampon[..ecrit]);
    Ok(&tampon[..n])
}

/// Ramène le chemin absolu `chemin` à sa forme simple, sur place, comme
/// `cd` de dash : sans « . », sans « / » en double ni à la fin, chaque
/// « .. » ôtant le nom qui le précède (pas au-dessus de la racine), sans
/// regarder si ce nom est un lien. Un « // » de tête reste (exactement
/// deux : POSIX laisse son sens à chaque système, et dash le garde, comme
/// une racine à part : `cd //tmp/..` donne « // ») ; trois ou plus n'en
/// font qu'un. Rend sa nouvelle longueur.
pub fn forme_simple(chemin: &mut [u8]) -> usize {
    let double = chemin.len() >= 2 && chemin[1] == b'/' && chemin.get(2) != Some(&b'/');
    // Ce qui est écrit : « » ou « /a/b » ; avec « // », « / » d'abord (le
    // premier caractère du chemin), puis « /a/b » à sa suite.
    let base = double as usize;
    let mut fin = base;
    let mut i = base;
    while i < chemin.len() {
        while i < chemin.len() && chemin[i] == b'/' {
            i += 1;
        }
        let debut = i;
        while i < chemin.len() && chemin[i] != b'/' {
            i += 1;
        }
        match &chemin[debut..i] {
            b"" | b"." => {}
            b".." => fin = chemin[..fin].iter().rposition(|&o| o == b'/').unwrap_or(0).max(base),
            _ => {
                chemin[fin] = b'/';
                chemin.copy_within(debut..i, fin + 1);
                fin += 1 + i - debut;
            }
        }
    }
    if fin == base {
        chemin[..=base].fill(b'/');
        fin = base + 1;
    }
    fin
}

/// Découpe `ligne` en mots, dans `tampon` (au moins `taille_tampon(ligne)`
/// octets). Rend `None` pour une ligne sans commande (vide, ou seulement
/// un commentaire).
pub fn decouper<'t>(ligne: &[u8], tampon: &'t mut [u8]) -> Result<Option<Ligne<'t>>, Erreur> {
    if tampon.len() < taille_tampon(ligne) {
        return Err(Erreur::TamponTropPetit);
    }
    // `wait`, seul (des blancs et un commentaire autour) : la commande
    // interne de sh. Sans guillemets : on ne reconnaît que ce mot-là.
    let mots: &[u8] = match ligne.iter().position(|&o| o == b'#') {
        Some(p) if p == 0 || ligne[p - 1] == b' ' || ligne[p - 1] == b'\t' => &ligne[..p],
        _ => ligne,
    };
    let mut seuls = mots.split(|&o| o == b' ' || o == b'\t').filter(|m| !m.is_empty());
    match seuls.next() {
        Some(b"wait") => return if seuls.next().is_none() { Ok(Some(Ligne::Attendre)) } else { Err(Erreur::Attendre) },
        Some(b"cd") => return dossier(ligne, tampon).map(|d| Some(Ligne::Dossier(d))),
        // `A=1 cd /x` : dash n'y changerait le dossier que pour cd lui-même.
        // (Le premier mot qui n'est pas une affectation : `A=1 /bin/x cd`
        // lance /bin/x.)
        Some(m) if est_affectation(m) && seuls.find(|m| !est_affectation(m)) == Some(&b"cd"[..]) => return Err(Erreur::Cd),
        _ => {}
    }
    let mut ecrit = 0; // Ce qui est écrit dans le tampon.
    let mut i = 0;
    // Tant qu'on n'a vu que des affectations et des options, le mot suivant
    // peut encore en être une.
    let mut en_tete = true;
    let mut programme = false;
    let mut arriere_plan = false;
    loop {
        // Les blancs entre deux mots.
        while i < ligne.len() && (ligne[i] == b' ' || ligne[i] == b'\t') {
            i += 1;
        }
        if i == ligne.len() || ligne[i] == b'#' {
            break;
        }
        if arriere_plan {
            // Après `&` : un second `&` (`&&`), ou une autre commande.
            return Err(if ligne[i] == b'&' { Erreur::Caractere(b'&') } else { Erreur::ApresEsperluette });
        }
        if ligne[i] == b'&' {
            // `&` après un blanc : la fin de la commande.
            arriere_plan = true;
            i += 1;
            continue;
        }
        // Une redirection : `<`, ou un chiffre seul collé à `<` en tête d'un
        // mot (le IO_NUMBER de la grammaire de sh).
        let numero = match (ligne[i], ligne.get(i + 1)) {
            (b'<', _) => Some(0),
            (n @ b'0'..=b'9', Some(b'<')) => {
                i += 1;
                Some(n - b'0')
            }
            _ => None,
        };
        if let Some(n) = numero {
            i += 1; // Le `<`.
            // Les autres redirections de sh, qu'on n'a pas.
            if let Some(&o @ (b'<' | b'>' | b'&' | b'|' | b'(')) = ligne.get(i) {
                return Err(Erreur::Caractere(o));
            }
            while i < ligne.len() && (ligne[i] == b' ' || ligne[i] == b'\t') {
                i += 1;
            }
            // Pas de chemin : la fin, un commentaire, `&`, ou une autre
            // redirection (`<`, ou un chiffre collé à `<` : pour sh, un
            // numéro de descripteur, pas un mot ; dash dit « redirection
            // unexpected »).
            let redirection = ligne.get(i) == Some(&b'<')
                || (ligne.get(i).is_some_and(u8::is_ascii_digit) && ligne.get(i + 1) == Some(&b'<'));
            if i == ligne.len() || ligne[i] == b'#' || ligne[i] == b'&' || redirection {
                return Err(Erreur::RedirectionSansChemin);
            }
            // Le numéro en chiffre ASCII : un mot ne contient jamais d'octet
            // nul (il les sépare).
            tampon[ecrit] = b'r';
            tampon[ecrit + 1] = b'0' + n;
            ecrit += 2;
            lire_mot(ligne, &mut i, tampon, &mut ecrit)?;
            tampon[ecrit] = 0;
            ecrit += 1;
            continue;
        }
        // Un mot brut : jusqu'au prochain blanc hors des guillemets, ou un
        // `&` ou un `<` (des opérateurs pour sh, même collés au mot).
        let debut = i;
        let place = ecrit;
        ecrit += 1; // Le genre, écrit à la fin.
        lire_mot(ligne, &mut i, tampon, &mut ecrit)?;
        let brut = &ligne[debut..i];
        let genre = if en_tete && est_affectation(brut) {
            b'a'
        } else if en_tete && brut.starts_with(b"--dir=") {
            // Le chemin seul : on retire « --dir= » de ce qui est écrit.
            let mot = place + 1;
            tampon.copy_within(mot + 6..ecrit, mot);
            ecrit -= 6;
            if ecrit == mot {
                return Err(Erreur::DossierVide);
            }
            b'd'
        } else if en_tete && brut.starts_with(b"--tcplisten=") {
            // L'adresse et le port seuls, vérifiés ici : une ligne fautive
            // est refusée en entier, comme les autres.
            let mot = place + 1;
            tampon.copy_within(mot + 12..ecrit, mot);
            ecrit -= 12;
            if adresse_et_port(&tampon[mot..ecrit]).is_none() {
                return Err(Erreur::Ecoute);
            }
            b'e'
        } else {
            // Le premier mot qui n'est ni une affectation ni une option : le
            // programme, par son chemin absolu.
            if !programme && !(ecrit > place + 1 && tampon[place + 1] == b'/') {
                return Err(Erreur::CheminRelatif);
            }
            en_tete = false;
            programme = true;
            b'm'
        };
        tampon[place] = genre;
        tampon[ecrit] = 0;
        ecrit += 1;
    }
    match (ecrit, programme) {
        (0, _) if !arriere_plan => Ok(None),
        (_, false) => Err(Erreur::SansProgramme),
        _ => Ok(Some(Ligne::Commande(Commande { tampon: &tampon[..ecrit], arriere_plan }))),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn decoupe(ligne: &str) -> Result<Option<(Vec<std::string::String>, Vec<std::string::String>, Vec<std::string::String>)>, Erreur> {
        let mut tampon = std::vec![0u8; taille_tampon(ligne.as_bytes())];
        let texte = |m: &[u8]| std::string::String::from_utf8(m.to_vec()).unwrap();
        Ok(decouper(ligne.as_bytes(), &mut tampon)?.map(|l| match l {
            Ligne::Commande(c) => {
                (c.affectations().map(texte).collect(), c.dossiers().map(texte).collect(), c.arguments().map(texte).collect())
            }
            Ligne::Attendre => (Vec::new(), Vec::new(), std::vec!["wait".into()]),
            Ligne::Dossier(d) => (Vec::new(), Vec::new(), std::vec!["cd".into(), std::string::String::from_utf8(d.to_vec()).unwrap()]),
        }))
    }

    /// La ligne se lance-t-elle en arrière-plan ?
    fn fond(ligne: &str) -> bool {
        let mut tampon = std::vec![0u8; taille_tampon(ligne.as_bytes())];
        matches!(decouper(ligne.as_bytes(), &mut tampon), Ok(Some(Ligne::Commande(c))) if c.arriere_plan())
    }

    fn attendre(ligne: &str) -> bool {
        let mut tampon = std::vec![0u8; taille_tampon(ligne.as_bytes())];
        matches!(decouper(ligne.as_bytes(), &mut tampon), Ok(Some(Ligne::Attendre)))
    }

    #[test]
    fn arriere_plan_et_wait() {
        assert!(fond("/bin/x &") && fond("/bin/x a&") && fond("/bin/x 'a'& # rien") && fond("A=1 /bin/x b &   "));
        assert!(!fond("/bin/x") && !fond("/bin/x '&'") && !fond("/bin/x \"a&b\""));
        assert_eq!(mots("/bin/x a&"), ["/bin/x", "a"]);
        assert_eq!(decoupe("/bin/x & /bin/y"), Err(Erreur::ApresEsperluette));
        assert_eq!(decoupe("/bin/x &&"), Err(Erreur::Caractere(b'&')));
        assert_eq!(decoupe("/bin/x && /bin/y"), Err(Erreur::Caractere(b'&')));
        assert_eq!(decoupe("&"), Err(Erreur::SansProgramme));
        assert_eq!(decoupe("A=1 &"), Err(Erreur::SansProgramme));
        assert!(attendre("wait") && attendre("  wait\t") && attendre("wait # tout le monde"));
        for refus in ["wait 12", "wait &", "A=1 wait", "wait;"] {
            assert!(decoupe(refus).is_err(), "{refus}");
        }
        assert_eq!(decoupe("wait %1"), Err(Erreur::Attendre));
        // Pas la commande interne : un chemin, ou entre guillemets.
        assert_eq!(decoupe("'wait'"), Err(Erreur::CheminRelatif));
        assert_eq!(mots("/bin/wait"), ["/bin/wait"]);
        assert_eq!(decoupe("wait#x"), Err(Erreur::CheminRelatif));
    }

    fn mots(ligne: &str) -> Vec<std::string::String> {
        decoupe(ligne).unwrap().unwrap().2
    }

    #[test]
    fn mots_simples() {
        assert_eq!(mots("/bin/pile"), ["/bin/pile"]);
        assert_eq!(mots("  /bin/pile   un\tdeux  "), ["/bin/pile", "un", "deux"]);
        assert_eq!(mots("/bin/claude --version"), ["/bin/claude", "--version"]);
    }

    #[test]
    fn guillemets() {
        assert_eq!(mots("/bin/x \"deux mots\" 'et trois mots'"), ["/bin/x", "deux mots", "et trois mots"]);
        // Collés au reste du mot : un seul mot ; vides : un mot vide.
        assert_eq!(mots("/bin/x a\"b c\"d '' \"\""), ["/bin/x", "ab cd", "", ""]);
        // Tout est littéral entre guillemets simples, même $ et \.
        assert_eq!(mots("/bin/x '$HOME \\n \"'"), ["/bin/x", "$HOME \\n \""]);
        // Un guillemet simple entre guillemets doubles, et l'inverse.
        assert_eq!(mots("/bin/x \"l'eau\" 'dit \"oui\"'"), ["/bin/x", "l'eau", "dit \"oui\""]);
        assert_eq!(decoupe("/bin/x \"pas fini"), Err(Erreur::GuillemetNonFerme));
        assert_eq!(decoupe("/bin/x 'pas fini"), Err(Erreur::GuillemetNonFerme));
        for interdit in ["\"$HOME\"", "\"`date`\"", "\"a\\b\""] {
            assert!(matches!(decoupe(&std::format!("/bin/x {interdit}")), Err(Erreur::Caractere(_))), "{interdit}");
        }
    }

    #[test]
    fn caracteres_speciaux_refuses() {
        for c in ["$", "*", "?", ";", "|", ">", "(", ")", "`", "\\", "~", "[", "]", "{", "}", "!", "^"] {
            assert_eq!(decoupe(&std::format!("/bin/x a{c}b")), Err(Erreur::Caractere(c.as_bytes()[0])), "{c}");
        }
        // Un octet de contrôle, même entre guillemets.
        assert_eq!(decoupe("/bin/x a\rb"), Err(Erreur::Caractere(b'\r')));
        assert_eq!(decoupe("/bin/x 'a\0b'"), Err(Erreur::Caractere(0)));
        // Ce que sh laisse tel quel.
        assert_eq!(mots("/bin/x a,b:c+d@e%f-g_h.i/j k#l é"), ["/bin/x", "a,b:c+d@e%f-g_h.i/j", "k#l", "é"]);
    }

    #[test]
    fn commentaires_et_lignes_vides() {
        assert_eq!(decoupe(""), Ok(None));
        assert_eq!(decoupe("   \t "), Ok(None));
        assert_eq!(decoupe("# un commentaire"), Ok(None));
        assert_eq!(decoupe("   # indente"), Ok(None));
        assert_eq!(mots("/bin/x un # deux"), ["/bin/x", "un"]);
        // # au milieu d'un mot, ou entre guillemets : un caractère comme un
        // autre.
        assert_eq!(mots("/bin/x a#b '#c'"), ["/bin/x", "a#b", "#c"]);
    }

    #[test]
    fn affectations_et_dossiers() {
        let (a, d, m) = decoupe("HOME=/tmp A_1='deux mots' --dir=/etc --dir=/ /bin/lecteur.wasm X=1 --dir=/tmp").unwrap().unwrap();
        assert_eq!(a, ["HOME=/tmp", "A_1=deux mots"]);
        assert_eq!(d, ["/etc", "/"]);
        // Après le programme, plus rien n'est une affectation ni une option.
        assert_eq!(m, ["/bin/lecteur.wasm", "X=1", "--dir=/tmp"]);
        // Pas des affectations : un nom invalide (1A, A+ : l'ajout de bash),
        // ou un guillemet avant le « = » ; le mot est alors le programme,
        // qui n'est pas un chemin absolu.
        for ligne in ["1A=x /bin/y", "\"A=x\" /bin/y", "=x /bin/y", "A+=x /bin/y"] {
            assert_eq!(decoupe(ligne), Err(Erreur::CheminRelatif), "{ligne}");
        }
        // _ est un nom comme un autre (pour dash).
        assert_eq!(decoupe("_=x /bin/y").unwrap().unwrap().0, ["_=x"]);
        // Une valeur vide, ou entre guillemets : permise.
        assert_eq!(decoupe("A= B=\"x y\" /bin/y").unwrap().unwrap().0, ["A=", "B=x y"]);
        // Sans programme.
        assert_eq!(decoupe("A=1"), Err(Erreur::SansProgramme));
        assert_eq!(decoupe("A=1 --dir=/etc # rien"), Err(Erreur::SansProgramme));
        assert_eq!(decoupe("--dir= /bin/x"), Err(Erreur::DossierVide));
        assert_eq!(decoupe("--dir=\"\" /bin/x"), Err(Erreur::DossierVide));
    }

    /// Les écoutes : rangées à part, leur adresse et leur port lus ; après
    /// le programme, un argument comme un autre ; une valeur qui n'est pas
    /// ADRESSE:PORT d'IPv4 en chiffres refuse la ligne.
    #[test]
    fn ecoutes() {
        let ligne = "--dir=/ --tcplisten=127.0.0.1:8080 --tcplisten='0.0.0.0:0' /bin/s.wasm --tcplisten=1.2.3.4:5";
        let mut tampon = std::vec![0u8; taille_tampon(ligne.as_bytes())];
        let Ok(Some(Ligne::Commande(c))) = decouper(ligne.as_bytes(), &mut tampon) else { panic!("{ligne}") };
        let e: Vec<_> = c.ecoutes().collect();
        assert_eq!(e, [([127, 0, 0, 1], 8080, &b"127.0.0.1:8080"[..]), ([0; 4], 0, &b"0.0.0.0:0"[..])]);
        assert_eq!(c.dossiers().collect::<Vec<_>>(), [b"/"]);
        assert_eq!(c.arguments().collect::<Vec<_>>(), [&b"/bin/s.wasm"[..], b"--tcplisten=1.2.3.4:5"]);
        for v in ["", "8080", "127.0.0.1", "127.0.0.1:", ":80", "127.0.0:1", "127.0.0.1.2:1", "256.0.0.1:1", "01.0.0.1:1",
                  "1.2.3.4:65536", "1.2.3.4:080", "1.2.3.4:-1", "localhost:80", "[::1]:80", "1..2.3:4", "1.2.3.4:5:6"] {
            assert_eq!(decoupe(&std::format!("--tcplisten='{v}' /bin/x")), Err(Erreur::Ecoute), "{v}");
        }
        assert_eq!(adresse_et_port(b"255.255.255.255:65535"), Some(([255; 4], 65535)));
        assert_eq!(adresse_et_port(b"10.0.2.15:0"), Some(([10, 0, 2, 15], 0)));
    }

    /// Les redirections d'une ligne : (descripteur, chemin), et ses arguments.
    fn redir(ligne: &str) -> Result<(Vec<(u8, std::string::String)>, Vec<std::string::String>, Vec<std::string::String>), Erreur> {
        let mut tampon = std::vec![0u8; taille_tampon(ligne.as_bytes())];
        let texte = |m: &[u8]| std::string::String::from_utf8(m.to_vec()).unwrap();
        match decouper(ligne.as_bytes(), &mut tampon)? {
            Some(Ligne::Commande(c)) => Ok((c.redirections().map(|(n, m)| (n, texte(m))).collect(),
                                           c.affectations().map(texte).collect(), c.arguments().map(texte).collect())),
            _ => panic!("{ligne} : pas une commande"),
        }
    }

    /// Les redirections, d'après `dash` (la relecture du plan de 6i les y a
    /// mesurées) : un seul chiffre collé au `<` et en tête de son mot fait
    /// un numéro ; tout autre mot collé reste un argument.
    #[test]
    fn redirections() {
        let r = |v: &[(u8, &str)]| v.iter().map(|&(n, c)| (n, c.into())).collect::<Vec<_>>();
        let a = |v: &[&str]| v.iter().map(|&m| m.into()).collect::<Vec<std::string::String>>();
        assert_eq!(redir("/bin/x 3<f").unwrap(), (r(&[(3, "f")]), a(&[]), a(&["/bin/x"])));
        assert_eq!(redir("/bin/x 3 <f").unwrap(), (r(&[(0, "f")]), a(&[]), a(&["/bin/x", "3"])));
        assert_eq!(redir("/bin/x a3<f").unwrap(), (r(&[(0, "f")]), a(&[]), a(&["/bin/x", "a3"])));
        assert_eq!(redir("/bin/x '3'<f").unwrap(), (r(&[(0, "f")]), a(&[]), a(&["/bin/x", "3"])));
        assert_eq!(redir("/bin/x 10<f").unwrap(), (r(&[(0, "f")]), a(&[]), a(&["/bin/x", "10"])));
        assert_eq!(redir("/bin/x 03<f").unwrap(), (r(&[(0, "f")]), a(&[]), a(&["/bin/x", "03"])));
        // Collé ou non au chemin, guillemets compris ; dans l'ordre de la
        // ligne ; avant le programme, les mots suivants restent en tête.
        assert_eq!(redir("/bin/x < 'a b' 3<\"c\" d").unwrap(), (r(&[(0, "a b"), (3, "c")]), a(&[]), a(&["/bin/x", "d"])));
        assert_eq!(redir("<f A=1 B=2 /bin/x").unwrap(), (r(&[(0, "f")]), a(&["A=1", "B=2"]), a(&["/bin/x"])));
        assert_eq!(redir("/bin/x<f").unwrap(), (r(&[(0, "f")]), a(&[]), a(&["/bin/x"])));
        assert_eq!(redir("/bin/x < a < b").unwrap(), (r(&[(0, "a"), (0, "b")]), a(&[]), a(&["/bin/x"])));
        // Avec `&` : l'entrée donnée remplace celle de l'arrière-plan.
        assert!(fond("/bin/x <f&") && fond("/bin/x < f &"));
        assert_eq!(redir("/bin/x <f&").unwrap().0, r(&[(0, "f")]));
        // Un chemin vide est permis (sh dira qu'il ne peut pas l'ouvrir).
        assert_eq!(redir("/bin/x < ''").unwrap().0, r(&[(0, "")]));
        // Sans chemin ; les autres redirections de sh.
        for ligne in ["/bin/x <", "/bin/x < #x", "/bin/x 3<", "/bin/x < &", "<"] {
            assert_eq!(decoupe(ligne), Err(Erreur::RedirectionSansChemin), "{ligne}");
        }
        // Une redirection là où sh attend le chemin : refusée, et par dash
        // aussi (« redirection unexpected »).
        for ligne in ["/bin/x < 3<g", "/bin/x <3<g", "/bin/x 3<4<g", "/bin/x < <g", "/bin/x 3< <g"] {
            assert_eq!(decoupe(ligne), Err(Erreur::RedirectionSansChemin), "{ligne}");
            let sortie = std::process::Command::new("sh").arg("-n").arg("-c").arg(ligne).output().unwrap();
            assert!(!sortie.status.success(), "sh accepte {ligne}");
        }
        for (ligne, c) in [("/bin/x <<f", b'<'), ("/bin/x <>f", b'>'), ("/bin/x <&3", b'&'), ("/bin/x <|f", b'|'),
                           ("/bin/x <(f)", b'('), ("/bin/x >f", b'>'), ("/bin/x 2>f", b'>')] {
            assert_eq!(decoupe(ligne), Err(Erreur::Caractere(c)), "{ligne}");
        }
        // Des redirections sans programme.
        assert_eq!(decoupe("<f"), Err(Erreur::SansProgramme));
        assert_eq!(decoupe("A=1 3<f"), Err(Erreur::SansProgramme));
    }

    /// Ce que nous ouvrons, `sh` l'ouvre aussi : pour chaque ligne, sh lance
    /// `readlink` à la place du programme, qui dit ce que désigne chacun de
    /// ses descripteurs 0 à 9 ; on compare aux redirections découpées.
    #[test]
    fn redirections_comme_sh() {
        let dossier = std::env::temp_dir().join(std::format!("commande-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        for nom in ["a", "b", "c d"] {
            std::fs::write(dossier.join(nom), nom).unwrap();
        }
        let d = dossier.to_str().unwrap();
        let lignes = [
            std::format!("/bin/x < {d}/a"),
            std::format!("/bin/x 3<{d}/a un < '{d}/c d'"),
            std::format!("<{d}/b A=1 /bin/x 7<{d}/a"),
            std::format!("/bin/x 5<{d}/a 5<{d}/b"),
            std::format!("/bin/x 3 <{d}/b"),
        ];
        for ligne in &lignes {
            let (redirections, _, _) = redir(ligne).unwrap();
            // Le programme et ses arguments remplacés par readlink, les
            // redirections et les affectations gardées : on retire les mots
            // qui ne sont ni l'un ni l'autre.
            let mut attendu: std::collections::BTreeMap<u8, std::string::String> = std::collections::BTreeMap::new();
            for (n, c) in &redirections {
                attendu.insert(*n, std::fs::canonicalize(c).unwrap().to_str().unwrap().into());
            }
            let script = std::format!(
                "{} /usr/bin/env sh -c 'for n in 0 1 2 3 4 5 6 7 8 9; do printf \"%s %s\\n\" $n \"$(readlink /proc/$$/fd/$n)\"; done'",
                ligne.replace("/bin/x", "").replace(" un ", " ").replace(" 3 <", " <"));
            let sortie = std::process::Command::new("sh").arg("-c").arg(&script).output().unwrap();
            let texte = std::string::String::from_utf8(sortie.stdout).unwrap();
            for l in texte.lines() {
                let (n, cible) = l.split_once(' ').unwrap();
                let n: u8 = n.parse().unwrap();
                if let Some(c) = attendu.get(&n) {
                    assert_eq!(cible, c, "{ligne} : descripteur {n}");
                } else if n >= 3 {
                    assert!(cible.is_empty() || !cible.starts_with(d), "{ligne} : descripteur {n} ouvert par sh : {cible}");
                }
            }
        }
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Le chemin d'une ligne `cd`.
    fn cd(ligne: &str) -> Result<std::string::String, Erreur> {
        let mut tampon = std::vec![0u8; taille_tampon(ligne.as_bytes())];
        match decouper(ligne.as_bytes(), &mut tampon)? {
            Some(Ligne::Dossier(d)) => Ok(std::string::String::from_utf8(d.to_vec()).unwrap()),
            _ => panic!("{ligne} : pas un cd"),
        }
    }

    #[test]
    fn cd_seul() {
        assert_eq!(cd("cd /tmp").unwrap(), "/tmp");
        assert_eq!(cd("  cd\t'/a b'  # commentaire").unwrap(), "/a b");
        assert_eq!(cd("cd /a/./b/../c//").unwrap(), "/a/c");
        assert_eq!(cd("cd /../..").unwrap(), "/");
        assert_eq!(cd("cd /").unwrap(), "/");
        // Un `#` dans un mot ou entre guillemets n'est pas un commentaire.
        assert_eq!(cd("cd '/a #b'").unwrap(), "/a #b");
        assert_eq!(cd("cd /a#b # c").unwrap(), "/a#b");
        assert_eq!(cd("cd # /a"), Err(Erreur::Cd));
        // « cd » en argument, après une affectation : un programme.
        assert_eq!(mots("A=1 /bin/x cd"), ["/bin/x", "cd"]);
        for refus in ["cd", "cd tmp", "cd /a /b", "cd /a &", "A=1 cd /a", "cd ''", "cd /a <f"] {
            assert!(decoupe(refus).is_err(), "{refus}");
        }
        assert_eq!(decoupe("cd"), Err(Erreur::Cd));
        assert_eq!(decoupe("A=1 cd /a"), Err(Erreur::Cd));
        // Pas la commande interne : un chemin, ou entre guillemets.
        assert_eq!(decoupe("'cd' /tmp"), Err(Erreur::CheminRelatif));
        assert_eq!(mots("/bin/cd /tmp"), ["/bin/cd", "/tmp"]);
    }

    /// La forme simple d'un chemin, et le PWD que dash donne après `cd` :
    /// les mêmes. Avec des dossiers qui existent (dash refuse les autres),
    /// et un lien : dash ne le suit pas pour calculer PWD (`cd -L`).
    #[test]
    fn cd_comme_sh() {
        let dossier = std::env::temp_dir().join(std::format!("commande-cd-{}", std::process::id()));
        std::fs::create_dir_all(dossier.join("a/b")).unwrap();
        let _ = std::os::unix::fs::symlink(dossier.join("a/b"), dossier.join("lien"));
        let d = dossier.to_str().unwrap();
        for chemin in [std::format!("{d}/a/b"), std::format!("{d}/./a//b/"), std::format!("{d}/a/b/../b/.."),
                       std::format!("{d}/lien/.."), std::format!("{d}/lien"), "/".into(), "/tmp/..".into(),
                       "//tmp".into(), "//".into(), "//tmp/..".into(), "///tmp".into(), "//tmp/./../tmp".into()] {
            let script = std::format!("cd '{chemin}' && printf %s \"$PWD\"");
            let sortie = std::process::Command::new("sh").arg("-c").arg(&script).env_clear().output().unwrap();
            assert!(sortie.status.success(), "{chemin}");
            assert_eq!(cd(&std::format!("cd '{chemin}'")).unwrap(), std::string::String::from_utf8(sortie.stdout).unwrap(), "{chemin}");
        }
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Le programme par son chemin absolu : ni un chemin relatif, ni un mot
    /// que sh comprendrait autrement (un mot réservé, une commande interne),
    /// même entre guillemets.
    #[test]
    fn chemin_absolu() {
        for ligne in ["bin/x", "./x", "x", "if /bin/x", "exec /bin/x", ". /bin/x", ": /bin/x", "\"\" /bin/x", "~/x", "A=1 x"] {
            assert!(matches!(decoupe(ligne), Err(Erreur::CheminRelatif | Erreur::Caractere(_))), "{ligne}");
        }
        assert_eq!(decoupe("if /bin/x"), Err(Erreur::CheminRelatif));
        // Un chemin absolu, même entre guillemets : oui ; et les arguments
        // suivants n'ont pas à l'être.
        assert_eq!(mots("'/bin/deux mots' x ./y"), ["/bin/deux mots", "x", "./y"]);
    }

    #[test]
    fn tampon() {
        let ligne = b"/a b c d e f";
        let mut petit = [0u8; 10];
        assert_eq!(decouper(ligne, &mut petit).map(|_| ()), Err(Erreur::TamponTropPetit));
        // La taille promise suffit même au pire cas : des mots d'un octet,
        // ou des mots vides.
        for ligne in ["/a b c d e f g", "/x '' '' '' ''", "/x", "A=1 B=2 /bin/x", "--dir=/ /x"] {
            let mut t = std::vec![0u8; taille_tampon(ligne.as_bytes())];
            assert!(decouper(ligne.as_bytes(), &mut t).is_ok(), "{ligne}");
        }
    }

    #[test]
    fn lignes_numerotees() {
        let v: Vec<_> = lignes(b"un\n\ndeux\ntrois").collect();
        assert_eq!(v, [(1, &b"un"[..]), (2, &b""[..]), (3, &b"deux"[..]), (4, &b"trois"[..])]);
        assert_eq!(lignes(b"un\n").count(), 1);
        assert_eq!(lignes(b"").count(), 0);
        assert_eq!(lignes(b"\n").count(), 1);
    }

    #[test]
    fn messages_sans_accents() {
        for e in [Erreur::GuillemetNonFerme, Erreur::Caractere(b'$'), Erreur::Caractere(1), Erreur::DossierVide, Erreur::Ecoute,
                  Erreur::SansProgramme, Erreur::CheminRelatif, Erreur::TamponTropPetit, Erreur::ApresEsperluette,
                  Erreur::Attendre, Erreur::RedirectionSansChemin, Erreur::Cd] {
            assert!(std::format!("{e}").is_ascii());
        }
    }

    /// Le cœur de la promesse : ce que nous acceptons, le `sh` de la
    /// machine le découpe pareil. Pour chaque ligne, sh reçoit les mêmes
    /// octets ; il affiche ses arguments (printf '%s\0') et son
    /// environnement (env -0). Les options --dir= et --tcplisten= (nos
    /// seules entorses) n'y sont pas.
    #[test]
    fn comme_sh() {
        let lignes = [
            "/bin/x",
            "/bin/x un deux\ttrois",
            "/bin/x \"deux mots\" 'et trois' a\"b c\"d '' \"\"",
            "/bin/x '$HOME \\n \"' \"l'eau\" 'dit \"oui\"'",
            "/bin/x a,b:c+d@e%f-g_h.i/j k#l é # commentaire",
            "A=1 B='deux mots' C=\"x y\" D= /bin/x a=b",
            "A_B=x /bin/x \"C=y\"",
            "_=x /bin/x",
            "/bin/x if then fi exec . :",
            "/bin/claude -p \"bonjour\"",
            "DISABLE_AUTOUPDATER=1 /bin/claude -p \"bonjour, ca va ?\"",
            "/bin/x a b &",
            "A=1 /bin/x 'c d'& # en arriere-plan",
            "wait",
        ];
        for ligne in lignes {
            // sh accepte la ligne telle quelle (-n : lue, pas exécutée) ;
            // pour comparer les mots, sans son `&` (sh lancerait la
            // commande en arrière-plan avant d'afficher quoi que ce soit).
            let sortie = std::process::Command::new("sh").arg("-n").arg("-c").arg(ligne).output().unwrap();
            assert!(sortie.status.success(), "{ligne} : refusee par sh");
            let ligne = &*ligne.replace("&", "");
            let (affectations, dossiers, arguments) = decoupe(ligne).unwrap().unwrap();
            assert!(dossiers.is_empty());
            // Les arguments : `set --` les reçoit tels que sh les découpe
            // (sans exécuter le programme). Les affectations en tête sont
            // retirées de la ligne pour cette partie.
            let sans_affectations: Vec<&str> = {
                let mut reste = ligne;
                for _ in &affectations {
                    reste = reste.trim_start();
                    let fin = mot_brut(reste);
                    reste = &reste[fin..];
                }
                std::vec![reste]
            };
            // (Une fin de ligne après : un commentaire de la ligne ne doit pas
            // avaler le printf.)
            let script = std::format!("set -- {}\nprintf '%s\\0' \"$@\"", sans_affectations[0]);
            let sortie = std::process::Command::new("sh").arg("-c").arg(&script).output().unwrap();
            let de_sh: Vec<_> = sortie.stdout.split(|&o| o == 0).collect();
            let de_sh: Vec<_> = de_sh[..de_sh.len() - 1].iter().map(|m| std::string::String::from_utf8(m.to_vec()).unwrap()).collect();
            assert_eq!(de_sh, arguments, "{ligne}");
            // Les affectations : dans l'environnement que sh donne à la
            // commande (ici env, qui l'affiche).
            if !affectations.is_empty() {
                let tete = &ligne[..ligne.len() - sans_affectations[0].len()];
                let script = std::format!("{tete} env -0");
                let sortie = std::process::Command::new("sh").arg("-c").arg(&script).output().unwrap();
                let env: Vec<_> = sortie.stdout.split(|&o| o == 0).map(|m| std::string::String::from_utf8(m.to_vec()).unwrap()).collect();
                for a in &affectations {
                    assert!(env.contains(a), "{ligne} : {a} absent de l'environnement de sh");
                }
            }
        }
    }

    /// La longueur du premier mot brut de `texte` (guillemets compris).
    fn mot_brut(texte: &str) -> usize {
        let o = texte.as_bytes();
        let mut i = 0;
        while i < o.len() && o[i] != b' ' && o[i] != b'\t' {
            if o[i] == b'\'' || o[i] == b'"' {
                i += 1 + o[i + 1..].iter().position(|&c| c == o[i]).unwrap();
            }
            i += 1;
        }
        i
    }
}
