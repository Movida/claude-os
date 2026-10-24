//! Lecture des octets d'un module binaire : entiers LEB128, flottants, noms.
//!
//! Le format binaire de WebAssembly écrit presque tous ses entiers en
//! LEB128 (« Little Endian Base 128 ») : 7 bits utiles par octet, du poids
//! faible au poids fort, et le bit 7 à 1 tant qu'il reste des octets. Ainsi
//! un petit nombre (un index, une taille) tient en un seul octet :
//!     5        -> 0x05
//!     300      -> 0xAC 0x02   (300 = 0b10_0101100 : 0101100 puis 10)
//! Les entiers signés utilisent le même principe ; le bit 6 du dernier octet
//! donne le signe, qu'on recopie dans les bits de poids fort.
//!
//! La spécification est stricte, et la suite de tests le vérifie : un u32
//! tient en 5 octets au plus, et les bits du dernier octet qui dépassent les
//! 32 bits doivent être nuls (ou, pour un signé, égaux au signe). Un
//! encodeur paresseux qui écrirait 0x80 0x80 0x80 0x80 0x80 0x00 pour 0 est
//! refusé : sinon, deux modules différents octet par octet pourraient avoir
//! le même sens, et un vérificateur et un interpréteur pourraient ne pas lire
//! la même chose.

use crate::erreur::{Erreur, Genre};

/// Un curseur sur une tranche d'octets. Il ne copie rien : les noms et les
/// corps de fonctions restent des sous-tranches du module d'origine tant
/// qu'on ne les recopie pas explicitement.
pub struct Lecteur<'a> {
    octets: &'a [u8],
    position: usize,
    /// Position du premier octet dans le module entier : les erreurs donnent
    /// une position absolue, utile pour regarder le fichier avec xxd.
    origine: usize,
}

impl<'a> Lecteur<'a> {
    pub fn new(octets: &'a [u8]) -> Self {
        Lecteur { octets, position: 0, origine: 0 }
    }

    /// Un lecteur sur `octets`, placé à la position `debut`.
    pub fn a_partir(octets: &'a [u8], debut: usize) -> Self {
        Lecteur { octets: &octets[debut..], position: 0, origine: debut }
    }

    pub fn position(&self) -> usize {
        self.origine + self.position
    }

    pub fn fini(&self) -> bool {
        self.position == self.octets.len()
    }

    pub fn reste(&self) -> usize {
        self.octets.len() - self.position
    }

    pub fn erreur(&self, genre: Genre) -> Erreur {
        Erreur { position: self.position(), genre }
    }

    pub fn octet(&mut self) -> Result<u8, Erreur> {
        let octet = *self.octets.get(self.position).ok_or(self.erreur(Genre::FinInattendue))?;
        self.position += 1;
        Ok(octet)
    }

    /// Les `n` octets suivants, tels quels.
    pub fn octets(&mut self, n: usize) -> Result<&'a [u8], Erreur> {
        if n > self.reste() {
            return Err(self.erreur(Genre::FinInattendue));
        }
        let tranche = &self.octets[self.position..self.position + n];
        self.position += n;
        Ok(tranche)
    }

    /// Un sous-lecteur sur les `n` octets suivants : pour lire une section ou
    /// un corps de fonction sans pouvoir déborder sur la suite.
    pub fn sous_lecteur(&mut self, n: usize) -> Result<Lecteur<'a>, Erreur> {
        let origine = self.position();
        let octets = self.octets(n)?;
        Ok(Lecteur { octets, position: 0, origine })
    }

    /// Entier non signé LEB128 d'au plus `bits` bits.
    fn non_signe(&mut self, bits: u32) -> Result<u64, Erreur> {
        let mut valeur: u64 = 0;
        let mut decalage = 0;
        loop {
            let octet = self.octet()?;
            let utiles = (octet & 0x7F) as u64;
            // Dernier octet permis : ses bits au-delà de `bits` doivent être
            // nuls (sinon le nombre ne tient pas dans le type).
            if decalage + 7 >= bits {
                let en_trop = utiles >> (bits - decalage);
                if octet & 0x80 != 0 {
                    return Err(self.erreur(Genre::EntierTropLong));
                }
                if en_trop != 0 {
                    return Err(self.erreur(Genre::EntierTropGrand));
                }
                return Ok(valeur | utiles << decalage);
            }
            valeur |= utiles << decalage;
            if octet & 0x80 == 0 {
                return Ok(valeur);
            }
            decalage += 7;
        }
    }

    /// Entier signé LEB128 d'au plus `bits` bits.
    fn signe(&mut self, bits: u32) -> Result<i64, Erreur> {
        let mut valeur: i64 = 0;
        let mut decalage = 0;
        loop {
            let octet = self.octet()?;
            let utiles = (octet & 0x7F) as i64;
            if decalage + 7 >= bits {
                if octet & 0x80 != 0 {
                    return Err(self.erreur(Genre::EntierTropLong));
                }
                // Les bits du dernier octet au-delà de `bits` - 1 (le bit de
                // signe compris) doivent tous être égaux : tous à 0 pour un
                // positif, tous à 1 pour un négatif.
                let restants = bits - decalage; // Bits utiles dans cet octet.
                let haut = (octet as i8) << 1 >> restants; // Signe étendu.
                if haut != 0 && haut != -1 {
                    return Err(self.erreur(Genre::EntierTropGrand));
                }
                valeur |= utiles << decalage;
                // Étendre le signe depuis le bit `bits` - 1.
                let vide = 64 - bits;
                return Ok(valeur << vide >> vide);
            }
            valeur |= utiles << decalage;
            decalage += 7;
            if octet & 0x80 == 0 {
                // Le bit 6 du dernier octet est le signe : on l'étend.
                if octet & 0x40 != 0 {
                    valeur |= -1i64 << decalage;
                }
                return Ok(valeur);
            }
        }
    }

    pub fn u32(&mut self) -> Result<u32, Erreur> {
        Ok(self.non_signe(32)? as u32)
    }

    pub fn s32(&mut self) -> Result<i32, Erreur> {
        Ok(self.signe(32)? as i32)
    }

    /// Le type d'un bloc est un entier signé de 33 bits : les négatifs
    /// désignent un type de valeur (sur un octet), les positifs un index de
    /// type. 33 bits, pour que tout index u32 tienne en positif.
    pub fn s33(&mut self) -> Result<i64, Erreur> {
        self.signe(33)
    }

    pub fn s64(&mut self) -> Result<i64, Erreur> {
        self.signe(64)
    }

    /// Un flottant : ses 4 octets IEEE 754, petit-boutiste. On garde les
    /// bits tels quels (u32) : passer par un f32 pourrait modifier la charge
    /// d'un NaN, que WebAssembly doit conserver.
    pub fn f32(&mut self) -> Result<u32, Erreur> {
        let o = self.octets(4)?;
        Ok(u32::from_le_bytes([o[0], o[1], o[2], o[3]]))
    }

    pub fn f64(&mut self) -> Result<u64, Erreur> {
        let o = self.octets(8)?;
        let mut tableau = [0; 8];
        tableau.copy_from_slice(o);
        Ok(u64::from_le_bytes(tableau))
    }

    /// Un nombre d'éléments, avant un vecteur. Chaque élément occupe au moins
    /// un octet : un nombre plus grand que ce qui reste est forcément faux,
    /// et on le refuse tout de suite. Ce n'est qu'une borne grossière : elle
    /// ne suffit pas pour réserver d'avance la mémoire de n éléments (voir
    /// `vecteur` dans decodeur.rs).
    pub fn nombre(&mut self) -> Result<u32, Erreur> {
        let n = self.u32()?;
        if n as usize > self.reste() {
            return Err(self.erreur(Genre::FinInattendue));
        }
        Ok(n)
    }

    /// Un nom : sa longueur, puis ses octets, qui doivent être de l'UTF-8
    /// valide (la spécification l'exige ; core::str::from_utf8 le vérifie).
    pub fn nom(&mut self) -> Result<&'a str, Erreur> {
        let n = self.u32()? as usize;
        let octets = self.octets(n)?;
        core::str::from_utf8(octets).map_err(|_| self.erreur(Genre::Utf8Invalide))
    }
}
