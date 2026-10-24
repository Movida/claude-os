//! Le noyau, en Rust.
//!
//! Il est lancé par notre chargeur (../boot.asm) : processeur en mode long
//! 64 bits, pagination active (1er Gio projeté à l'identique), interruptions
//! coupées, noyau recopié à 1 Mio.

// Pas de bibliothèque standard : elle suppose un système d'exploitation
// (fichiers, fils d'exécution, allocation...). Il ne reste que `core` : les
// types, le formatage, les opérations atomiques.
#![no_std]
// Pas de `main` classique : personne ne prépare d'arguments ni d'environnement.
// Le point d'entrée est _start, ci-dessous.
#![no_main]

mod console;
mod port;
mod serie;
mod verrou;
mod vga;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

// Le point d'entrée, en assembleur : avant de pouvoir exécuter du Rust, il
// faut une pile (le code compilé y range variables et adresses de retour)
// et une .bss à zéro (le compilateur suppose que les variables statiques
// initialisées à zéro le sont vraiment). Placé dans .text.debut, que le
// script d'édition de liens met en tête de l'image : c'est là que le
// chargeur saute.
global_asm!(
    r#"
    .section .text.debut, "ax"
    .global _start
_start:
    lea rsp, [rip + __pile_haut]

    lea rdi, [rip + __bss_debut]
    lea rcx, [rip + __bss_fin]
    sub rcx, rdi
    xor eax, eax
    cld
    rep stosb

    call noyau_main
2:  cli
    hlt
    jmp 2b
    "#
);

unsafe extern "C" {
    // Défini dans le global_asm! ci-dessus : seule son adresse nous intéresse.
    static _start: u8;
}

#[unsafe(no_mangle)]
extern "C" fn noyau_main() -> ! {
    console::initialiser();
    afficherln!("[noyau] Bonjour depuis le noyau Rust !");
    afficherln!("[noyau] Mode long 64 bits, point d'entree a {:#x}.", &raw const _start as usize);
    arreter()
}

/// Arrête le processeur pour de bon : interruptions coupées, puis `hlt`.
/// La boucle reprend l'arrêt si une interruption non masquable (NMI) le
/// réveille.
fn arreter() -> ! {
    loop {
        // SAFETY : cli et hlt n'ont pas d'autre effet que d'arrêter le
        // processeur, ce qu'on veut ici.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Appelé par Rust en cas d'erreur fatale (indice hors d'un tableau,
/// unwrap() sur une erreur, panic! explicite...). Sans système en dessous,
/// on affiche ce qu'on sait et on arrête tout.
#[panic_handler]
fn panique(info: &PanicInfo) -> ! {
    afficherln!("[noyau] PANIQUE : {}", info);
    arreter()
}
