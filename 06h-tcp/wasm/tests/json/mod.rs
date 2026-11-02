//! Un petit analyseur JSON, juste ce qu'il faut pour lire les fichiers de
//! commandes produits par wast2json. Écrit à la main plutôt qu'avec une
//! crate (serde_json) : zéro dépendance, comme le reste du projet, et
//! JSON est un format assez simple pour tenir en une centaine de lignes.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Valeur {
    Nul,
    Booleen(bool),
    Nombre(f64),
    Texte(String),
    Tableau(Vec<Valeur>),
    Objet(BTreeMap<String, Valeur>),
}

impl Valeur {
    /// Le champ `cle` d'un objet, ou Nul.
    pub fn champ(&self, cle: &str) -> &Valeur {
        match self {
            Valeur::Objet(o) => o.get(cle).unwrap_or(&Valeur::Nul),
            _ => &Valeur::Nul,
        }
    }

    pub fn texte(&self) -> Option<&str> {
        match self {
            Valeur::Texte(t) => Some(t),
            _ => None,
        }
    }

    pub fn tableau(&self) -> &[Valeur] {
        match self {
            Valeur::Tableau(t) => t,
            _ => &[],
        }
    }

    pub fn nombre(&self) -> Option<f64> {
        match self {
            Valeur::Nombre(n) => Some(*n),
            _ => None,
        }
    }
}

pub fn analyser(texte: &str) -> Result<Valeur, String> {
    let mut a = Analyseur { octets: texte.as_bytes(), position: 0 };
    let v = a.valeur()?;
    a.espaces();
    if a.position != a.octets.len() {
        return Err(a.erreur("contenu apres la valeur"));
    }
    Ok(v)
}

struct Analyseur<'a> {
    octets: &'a [u8],
    position: usize,
}

impl Analyseur<'_> {
    fn erreur(&self, quoi: &str) -> String {
        format!("JSON, octet {} : {}", self.position, quoi)
    }

    fn espaces(&mut self) {
        while matches!(self.octets.get(self.position), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn attendre(&mut self, octet: u8) -> Result<(), String> {
        self.espaces();
        if self.octets.get(self.position) == Some(&octet) {
            self.position += 1;
            Ok(())
        } else {
            Err(self.erreur(&format!("'{}' attendu", octet as char)))
        }
    }

    fn mot(&mut self, mot: &str, valeur: Valeur) -> Result<Valeur, String> {
        if self.octets[self.position..].starts_with(mot.as_bytes()) {
            self.position += mot.len();
            Ok(valeur)
        } else {
            Err(self.erreur("mot inconnu"))
        }
    }

    fn valeur(&mut self) -> Result<Valeur, String> {
        self.espaces();
        match self.octets.get(self.position) {
            Some(b'{') => self.objet(),
            Some(b'[') => self.tableau(),
            Some(b'"') => Ok(Valeur::Texte(self.chaine()?)),
            Some(b't') => self.mot("true", Valeur::Booleen(true)),
            Some(b'f') => self.mot("false", Valeur::Booleen(false)),
            Some(b'n') => self.mot("null", Valeur::Nul),
            Some(b'-' | b'0'..=b'9') => self.nombre(),
            _ => Err(self.erreur("valeur attendue")),
        }
    }

    fn objet(&mut self) -> Result<Valeur, String> {
        self.attendre(b'{')?;
        let mut objet = BTreeMap::new();
        self.espaces();
        if self.octets.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(Valeur::Objet(objet));
        }
        loop {
            self.espaces();
            let cle = self.chaine()?;
            self.attendre(b':')?;
            objet.insert(cle, self.valeur()?);
            self.espaces();
            match self.octets.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(Valeur::Objet(objet));
                }
                _ => return Err(self.erreur("',' ou '}' attendu")),
            }
        }
    }

    fn tableau(&mut self) -> Result<Valeur, String> {
        self.attendre(b'[')?;
        let mut tableau = Vec::new();
        self.espaces();
        if self.octets.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(Valeur::Tableau(tableau));
        }
        loop {
            tableau.push(self.valeur()?);
            self.espaces();
            match self.octets.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(Valeur::Tableau(tableau));
                }
                _ => return Err(self.erreur("',' ou ']' attendu")),
            }
        }
    }

    fn nombre(&mut self) -> Result<Valeur, String> {
        let debut = self.position;
        while matches!(self.octets.get(self.position), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
            self.position += 1;
        }
        let texte = std::str::from_utf8(&self.octets[debut..self.position]).unwrap();
        texte.parse().map(Valeur::Nombre).map_err(|_| self.erreur("nombre invalide"))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let chiffres = self.octets.get(self.position..self.position + 4).ok_or(self.erreur("\\u incomplet"))?;
        let texte = std::str::from_utf8(chiffres).map_err(|_| self.erreur("\\u invalide"))?;
        self.position += 4;
        u32::from_str_radix(texte, 16).map_err(|_| self.erreur("\\u invalide"))
    }

    fn chaine(&mut self) -> Result<String, String> {
        self.attendre(b'"')?;
        let mut octets = Vec::new();
        loop {
            let octet = *self.octets.get(self.position).ok_or(self.erreur("chaine non terminee"))?;
            self.position += 1;
            match octet {
                b'"' => break,
                b'\\' => {
                    let echappe = *self.octets.get(self.position).ok_or(self.erreur("echappement incomplet"))?;
                    self.position += 1;
                    let c = match echappe {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            // \uXXXX ; au-delà de U+FFFF, une paire de
                            // « demi-codets » UTF-16 : \uD8xx\uDCxx.
                            let mut code = self.hex4()?;
                            if (0xD800..0xDC00).contains(&code)
                                && self.octets[self.position..].starts_with(b"\\u")
                            {
                                self.position += 2;
                                let bas = self.hex4()?;
                                code = 0x10000 + ((code - 0xD800) << 10) + (bas - 0xDC00);
                            }
                            // Un demi-codet isolé n'est pas un caractère :
                            // wast2json en produit pour certains noms
                            // invalides ; on le remplace.
                            char::from_u32(code).unwrap_or('\u{FFFD}')
                        }
                        _ => return Err(self.erreur("echappement inconnu")),
                    };
                    let mut tampon = [0; 4];
                    octets.extend_from_slice(c.encode_utf8(&mut tampon).as_bytes());
                }
                _ => octets.push(octet),
            }
        }
        String::from_utf8(octets).map_err(|_| self.erreur("chaine qui n'est pas de l'UTF-8"))
    }
}
