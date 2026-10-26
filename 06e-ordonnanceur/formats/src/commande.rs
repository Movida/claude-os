//! Les lignes de /etc/demarrage : ce que le noyau lance au démarrage.
//!
//! Sans `fork` ni `execve` (6k), aucun programme ne peut en lancer un autre :
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
//! au hasard). En 6k, le même fichier pourra donc être lancé tel quel par
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
//!   - LA SEULE ENTORSE à `sh` : des options `--dir=CHEMIN`, entre les
//!     affectations et le programme, donnent un dossier pré-ouvert à un
//!     programme WebAssembly (comme `wasmtime --dir`) ;
//!   - puis le programme, par son CHEMIN ABSOLU (qui devient aussi
//!     argv[0]), et ses arguments. Un mot qui commence par `/` n'est ni un
//!     mot réservé de sh (`if`, `while`...), ni une commande interne
//!     (`exec`, `.`, `:`), ni un alias : c'est ce qui rend la promesse vraie
//!     pour toute la ligne. Et le noyau n'a pas de `PATH` à chercher.
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
    /// Des affectations ou des options, mais pas de programme.
    SansProgramme,
    /// Le programme n'est pas un chemin absolu.
    CheminRelatif,
    /// Le tampon de l'appelant est trop petit (voir `taille_tampon`).
    TamponTropPetit,
}

// Affichés par le noyau : sans accents.
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Erreur::GuillemetNonFerme => f.write_str("guillemet non ferme"),
            Erreur::Caractere(c) if c.is_ascii_graphic() => write!(f, "caractere special '{}' hors des guillemets", *c as char),
            Erreur::Caractere(c) => write!(f, "octet {c:#04x} interdit"),
            Erreur::DossierVide => f.write_str("--dir= sans chemin"),
            Erreur::SansProgramme => f.write_str("pas de programme a lancer"),
            Erreur::CheminRelatif => f.write_str("le programme doit etre donne par son chemin absolu"),
            Erreur::TamponTropPetit => f.write_str("ligne trop longue"),
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
    /// Le programme, ou l'un de ses arguments.
    Argument,
}

/// Une ligne découpée : ses mots, guillemets retirés, dans le tampon de
/// l'appelant.
#[derive(Debug, Clone, Copy)]
pub struct Commande<'t> {
    tampon: &'t [u8],
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

    /// Le programme puis ses arguments : argv.
    pub fn arguments(&self) -> impl Iterator<Item = &'t [u8]> + 't {
        self.mots().filter(|(g, _)| *g == Genre::Argument).map(|(_, m)| m)
    }

    /// Le programme : le premier argument (toujours là, et un chemin
    /// absolu : vérifié).
    pub fn programme(&self) -> &'t [u8] {
        self.arguments().next().unwrap_or(&[])
    }
}

/// Un caractère que `sh` laisse tel quel hors des guillemets. (Les octets
/// de 0x80 et plus, l'UTF-8, aussi : `sh` ne les interprète pas.)
fn ordinaire(o: u8) -> bool {
    o.is_ascii_alphanumeric() || b"_-./,:+=@%#".contains(&o) || o >= 0x80
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

/// Découpe `ligne` en mots, dans `tampon` (au moins `taille_tampon(ligne)`
/// octets). Rend `None` pour une ligne sans commande (vide, ou seulement
/// un commentaire).
pub fn decouper<'t>(ligne: &[u8], tampon: &'t mut [u8]) -> Result<Option<Commande<'t>>, Erreur> {
    if tampon.len() < taille_tampon(ligne) {
        return Err(Erreur::TamponTropPetit);
    }
    let mut ecrit = 0; // Ce qui est écrit dans le tampon.
    let mut i = 0;
    // Tant qu'on n'a vu que des affectations et des options, le mot suivant
    // peut encore en être une.
    let mut en_tete = true;
    let mut programme = false;
    loop {
        // Les blancs entre deux mots.
        while i < ligne.len() && (ligne[i] == b' ' || ligne[i] == b'\t') {
            i += 1;
        }
        if i == ligne.len() || ligne[i] == b'#' {
            break;
        }
        // Un mot brut : jusqu'au prochain blanc hors des guillemets.
        let debut = i;
        let place = ecrit;
        ecrit += 1; // Le genre, écrit à la fin.
        while i < ligne.len() && ligne[i] != b' ' && ligne[i] != b'\t' {
            match ligne[i] {
                b'\'' => {
                    let fin = ligne[i + 1..].iter().position(|&o| o == b'\'').ok_or(Erreur::GuillemetNonFerme)?;
                    for &o in &ligne[i + 1..i + 1 + fin] {
                        if o == 0 || o == b'\n' {
                            return Err(Erreur::Caractere(o));
                        }
                        tampon[ecrit] = o;
                        ecrit += 1;
                    }
                    i += fin + 2;
                }
                b'"' => {
                    let fin = ligne[i + 1..].iter().position(|&o| o == b'"').ok_or(Erreur::GuillemetNonFerme)?;
                    for &o in &ligne[i + 1..i + 1 + fin] {
                        if o == b'$' || o == b'`' || o == b'\\' || o == 0 || o == b'\n' {
                            return Err(Erreur::Caractere(o));
                        }
                        tampon[ecrit] = o;
                        ecrit += 1;
                    }
                    i += fin + 2;
                }
                o if ordinaire(o) => {
                    tampon[ecrit] = o;
                    ecrit += 1;
                    i += 1;
                }
                o => return Err(Erreur::Caractere(o)),
            }
        }
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
        (0, _) => Ok(None),
        (_, false) => Err(Erreur::SansProgramme),
        _ => Ok(Some(Commande { tampon: &tampon[..ecrit] })),
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
        Ok(decouper(ligne.as_bytes(), &mut tampon)?.map(|c| {
            (c.affectations().map(texte).collect(), c.dossiers().map(texte).collect(), c.arguments().map(texte).collect())
        }))
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
        for c in ["$", "*", "?", ";", "&", "|", "<", ">", "(", ")", "`", "\\", "~", "[", "]", "{", "}", "!", "^"] {
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
        for e in [Erreur::GuillemetNonFerme, Erreur::Caractere(b'$'), Erreur::Caractere(1), Erreur::DossierVide,
                  Erreur::SansProgramme, Erreur::CheminRelatif, Erreur::TamponTropPetit] {
            assert!(std::format!("{e}").is_ascii());
        }
    }

    /// Le cœur de la promesse : ce que nous acceptons, le `sh` de la
    /// machine le découpe pareil. Pour chaque ligne, sh reçoit les mêmes
    /// octets ; il affiche ses arguments (printf '%s\0') et son
    /// environnement (env -0). Les options --dir= (notre seule entorse)
    /// n'y sont pas.
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
        ];
        for ligne in lignes {
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
