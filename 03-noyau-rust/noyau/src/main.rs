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

#[macro_use] // Les macros afficher! et afficherln! servent dans tous les modules.
mod console;
mod clavier;
mod cpu;
mod gdt;
mod horloge;
mod interruptions;
mod pic;
mod port;
mod serie;
mod verrou;
mod vga;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

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

    gdt::initialiser();
    interruptions::initialiser();
    afficherln!("[noyau] GDT, TSS et IDT du noyau en place.");

    // Test volontaire : int3 déclenche l'exception 3. Si l'IDT est fausse,
    // c'est une triple faute et QEMU redémarre ; sinon, on revient ici.
    // SAFETY : int3 ne fait qu'appeler notre gestionnaire, qui revient.
    unsafe { asm!("int3") };
    afficherln!("[noyau] Retour apres int3 : les exceptions sont gerees.");

    // Les interruptions matérielles : d'abord le PIC (tout masqué), puis
    // l'horloge qui démasque son IRQ, et seulement alors sti. Dans l'autre
    // ordre, une IRQ pourrait arriver sur un vecteur d'exception.
    pic::initialiser();
    horloge::initialiser();
    cpu::activer_interruptions();
    afficherln!("[noyau] PIC remappe sur les vecteurs {}-{}, horloge a {} Hz.",
                pic::VECTEUR_BASE, pic::VECTEUR_BASE + pic::NB_IRQ - 1, horloge::HZ);
    // Le compte affiché vaut 100, parfois 101 : un tic peut tomber entre
    // le réveil et la lecture du compteur.
    horloge::attendre_ms(100);
    afficherln!("[noyau] 100 ms plus tard : {} tics comptes.", horloge::tics());

    match clavier::initialiser() {
        Ok(()) => afficherln!("[noyau] Clavier PS/2 pret : tapez du texte."),
        Err(()) => afficherln!("[noyau] Pas de controleur clavier 8042 qui reponde."),
    }

    // La boucle principale : afficher ce qui est tapé, et dormir quand il
    // n'y a rien. On vérifie la file interruptions coupées, puis on dort
    // avec sti;hlt (voir cpu::attendre_interruption) : une touche tapée
    // entre les deux ne peut pas passer inaperçue.
    loop {
        cpu::couper_interruptions();
        if !clavier::en_attente() {
            cpu::attendre_interruption();
            continue;
        }
        cpu::activer_interruptions();
        while let Some(c) = clavier::lire_caractere() {
            afficher!("{}", c);
        }
    }
}

/// Appelé par Rust en cas d'erreur fatale (indice hors d'un tableau,
/// unwrap() sur une erreur, panic! explicite...). Sans système en dessous,
/// on affiche ce qu'on sait et on arrête tout.
#[panic_handler]
fn panique(info: &PanicInfo) -> ! {
    // Une panique pendant l'affichage de la panique (un bogue dans la
    // console elle-même) recommencerait sans fin : la deuxième fois, on
    // s'arrête sans rien dire.
    static EN_PANIQUE: AtomicBool = AtomicBool::new(false);
    if EN_PANIQUE.swap(true, Ordering::Relaxed) {
        cpu::arreter();
    }
    console::preparer_panique();
    afficherln!("[noyau] PANIQUE : {}", info);
    cpu::arreter()
}
