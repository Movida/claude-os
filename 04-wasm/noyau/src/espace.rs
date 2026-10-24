//! L'espace d'adressage virtuel du noyau : où se trouve quoi.
//!
//! Comme Linux sur x86_64, le noyau vit dans la moitié HAUTE des adresses
//! virtuelles, celles qui commencent par 0xffff :
//!
//!   0xffff_8880_0000_0000  la projection directe : la mémoire physique
//!                          entière, l'adresse physique p étant vue à cette
//!                          base + p (le « direct map » de Linux,
//!                          __PAGE_OFFSET). Le noyau y lit et écrit
//!                          n'importe quel cadre, la mémoire vidéo, les
//!                          tables du BIOS.
//!   0xffff_ffff_8000_0000  le noyau lui-même (__START_KERNEL_map) : son
//!                          image, chargée à l'adresse physique 1 Mio, s'y
//!                          exécute à 0xffff_ffff_8010_0000.
//!
//! Pourquoi en haut :
//!   - la moitié basse reste entière aux programmes (étape 6), avec des
//!     adresses qui commencent à 0, comme sous n'importe quel système ;
//!   - le noyau sera projeté dans l'espace d'adressage de chaque programme,
//!     toujours au même endroit : un appel système n'a pas à changer de
//!     tables de pages pour trouver le code du noyau ;
//!   - le « modèle de code kernel » du compilateur suppose le code dans les
//!     2 derniers Gio de l'espace : les adresses du noyau tiennent alors sur
//!     32 bits signés, et les instructions sont plus courtes.
//! Entre les deux moitiés, les adresses « non canoniques » (bits 47 à 63
//! qui ne sont pas tous égaux) n'existent pas : le processeur refuse de
//! s'en servir.
//!
//! Tant que les tables de démarrage (main.rs, _start) sont en place, la
//! projection directe ne couvre que le premier Gio de mémoire physique.

/// Le début de la projection directe.
pub const PROJECTION_DIRECTE: u64 = 0xffff_8880_0000_0000;

/// L'adresse virtuelle de l'adresse physique 0 dans la projection du noyau
/// (le noyau est à BASE_NOYAU + son adresse physique). linker.ld utilise
/// la même valeur.
pub const BASE_NOYAU: u64 = 0xffff_ffff_8000_0000;

/// L'adresse, dans la projection directe, d'une adresse physique.
pub const fn virtuelle(physique: u64) -> u64 {
    PROJECTION_DIRECTE + physique
}

/// L'adresse physique d'une adresse du noyau (son code, ses données, sa
/// pile).
pub fn physique_du_noyau(virtuelle: u64) -> u64 {
    virtuelle - BASE_NOYAU
}
