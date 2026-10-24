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
mod cadres;
mod carte_memoire;
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
// Le chargeur passe l'adresse de la carte de la mémoire dans rdi ; or
// rep stosb se sert de rdi : on la met de côté dans r15 le temps
// d'effacer la .bss, puis on la rend à rdi, 1er argument de noyau_main.
global_asm!(
    r#"
    .section .text.debut, "ax"
    .global _start
_start:
    lea rsp, [rip + __pile_haut]
    mov r15, rdi

    lea rdi, [rip + __bss_debut]
    lea rcx, [rip + __bss_fin]
    sub rcx, rdi
    xor eax, eax
    cld
    rep stosb

    mov rdi, r15
    call noyau_main
2:  cli
    hlt
    jmp 2b
    "#
);

unsafe extern "C" {
    // Défini dans le global_asm! ci-dessus : seule son adresse nous intéresse.
    static _start: u8;
    // Défini par le script d'édition de liens : la fin du noyau en mémoire
    // (après la .bss et la pile).
    static __bss_fin: u8;
}

#[unsafe(no_mangle)]
extern "C" fn noyau_main(carte: u64) -> ! {
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

    // La mémoire physique : la carte du BIOS, puis l'allocateur de cadres.
    // SAFETY : `carte` est l'adresse passée par notre chargeur, et rien n'a
    // encore réutilisé la mémoire basse.
    if let Err(e) = unsafe { carte_memoire::recopier(carte) } {
        panic!("carte de la memoire illisible ({})", e);
    }
    carte_memoire::afficher();
    let fin_noyau = &raw const __bss_fin as u64;
    match cadres::initialiser(fin_noyau) {
        Ok(bilan) => {
            afficherln!("[noyau] Memoire libre : {} cadres de 4 Kio ({} Mio).",
                        bilan.libres, bilan.libres as u64 * cadres::TAILLE_CADRE >> 20);
            afficherln!("        Carte de bits : {} Kio a {:#x}, apres le noyau (fin a {:#x}).",
                        bilan.taille_bits >> 10, bilan.adresse_bits, fin_noyau);
            if bilan.au_dela > 0 {
                afficherln!("        {} Mio au-dela du 1er Gio, pas encore projetes.", bilan.au_dela >> 20);
            }
        }
        Err(e) => panic!("allocateur de cadres : {}", e),
    }
    tester_cadres();

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

/// Vérifie l'allocateur : trois cadres distincts et alignés, et un cadre
/// rendu est bien redonné ensuite.
fn tester_cadres() {
    let libres_avant = cadres::libres();
    let a = cadres::allouer().expect("plus de memoire");
    let b = cadres::allouer().expect("plus de memoire");
    let c = cadres::allouer().expect("plus de memoire");
    assert!(a != b && b != c && a != c && (a | b | c) % cadres::TAILLE_CADRE == 0);
    // On écrit dans un cadre : il est bien projeté et à nous.
    // SAFETY : `b` vient d'être alloué, personne d'autre ne s'en sert.
    unsafe { core::ptr::write_bytes(b as *mut u8, 0, cadres::TAILLE_CADRE as usize) };
    cadres::liberer(b);
    let d = cadres::allouer().expect("plus de memoire");
    cadres::liberer(a);
    cadres::liberer(c);
    cadres::liberer(d);
    assert!(cadres::libres() == libres_avant);
    afficherln!("[noyau] Cadres alloues : {:#x} {:#x} {:#x} ; {:#x} rendu puis redonne : {}.",
                a, b, c, b, if d == b { "ok" } else { "ECHEC" });
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
