//! Le noyau, en Rust.
//!
//! Il est lancé par notre chargeur (../boot.asm) : processeur en mode long
//! 64 bits, pagination active (1er Gio projeté à l'identique), interruptions
//! coupées, noyau chargé à 1 Mio. C'est tout ce qu'il attend de lui : un
//! futur chargeur UEFI, qui laisse le processeur dans ce même état, n'aura
//! rien de plus à faire. Le noyau construit lui-même ses tables de pages et
//! s'installe dans la moitié haute de l'espace d'adressage (voir espace.rs).

// Pas de bibliothèque standard : elle suppose un système d'exploitation
// (fichiers, fils d'exécution, allocation...). Il ne reste que `core` : les
// types, le formatage, les opérations atomiques.
#![no_std]
// Pas de `main` classique : personne ne prépare d'arguments ni d'environnement.
// Le point d'entrée est _start, ci-dessous.
#![no_main]

// Les collections de Rust (Box, Vec, String), servies par notre tas (tas.rs).
extern crate alloc;

#[macro_use] // Les macros afficher! et afficherln! servent dans tous les modules.
mod console;
mod cadres;
mod carte_memoire;
mod clavier;
mod cpu;
mod espace;
mod gdt;
mod horloge;
mod interruptions;
mod pagination;
mod pages;
mod pic;
mod port;
mod serie;
mod tas;
mod verrou;
mod vga;
mod wasi;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

// Le point d'entrée, en assembleur : avant de pouvoir exécuter du Rust, il
// faut une pile (le code compilé y range variables et adresses de retour),
// une .bss à zéro (le compilateur suppose que les variables statiques
// initialisées à zéro le sont vraiment), et ici des tables de pages qui
// projettent le noyau là où il a été lié. Placé dans .text.debut, que le
// script d'édition de liens met en tête de l'image : c'est là que le
// chargeur saute.
//
// Le chargeur saute à l'adresse PHYSIQUE 0x100000, le premier Gio étant
// projeté à l'identique. Le noyau, lui, est lié pour s'exécuter en haut, à
// BASE_NOYAU + 0x100000 : jusqu'au saut, seules les adresses relatives à
// RIP (lea [rip + ...]) sont justes, et elles donnent des adresses
// physiques. C'est ce que fait startup_64, dans head_64.S de Linux.
//
// Les tables de démarrage, dans la .bss : une PD de 512 pages de 2 Mio
// couvre le premier Gio de mémoire physique, et trois PDPT la font voir à
// trois endroits (les index viennent des bits de l'adresse, voir
// ../02-mode-long/boot.asm) :
//   - à l'identique (PML4[0]), le temps de sauter en haut, puisque le code
//     s'exécute encore à son adresse physique ;
//   - dans la projection directe (PML4[273], 0xffff_8880_0000_0000) ;
//   - à la place du noyau (PML4[511] puis PDPT[510], 0xffff_ffff_8000_0000).
// Bits des entrées : 0x003 = présente, inscriptible ; 0x080 = page de 2 Mio.
// Ce sont des tables provisoires, à grosses pages, sans protection : le
// noyau les remplacera par les siennes, page par page.
//
// Le chargeur passe l'adresse de la carte de la mémoire dans rdi ; or
// rep stosb se sert de rdi : on la met de côté dans r15, puis on la rend à
// rdi, 1er argument de noyau_main.
global_asm!(
    r#"
    .section .text.debut, "ax"
    .global _start
_start:
    mov r15, rdi

    lea rdi, [rip + __bss_debut]
    lea rcx, [rip + __bss_fin]
    sub rcx, rdi
    xor eax, eax
    cld
    rep stosb

    lea rdi, [rip + demarrage_pd]
    mov eax, 0x83
    mov ecx, 512
1:  mov [rdi], rax
    add rax, 0x200000
    add rdi, 8
    dec ecx
    jnz 1b

    lea rax, [rip + demarrage_pd]
    or rax, 3
    mov [rip + demarrage_pdpt_identite], rax
    mov [rip + demarrage_pdpt_directe], rax
    mov [rip + demarrage_pdpt_noyau + 510 * 8], rax
    lea rax, [rip + demarrage_pdpt_identite]
    or rax, 3
    mov [rip + demarrage_pml4], rax
    lea rax, [rip + demarrage_pdpt_directe]
    or rax, 3
    mov [rip + demarrage_pml4 + 273 * 8], rax
    lea rax, [rip + demarrage_pdpt_noyau]
    or rax, 3
    mov [rip + demarrage_pml4 + 511 * 8], rax
    lea rax, [rip + demarrage_pml4]
    mov cr3, rax

    /* Le saut en haut : par l'adresse ABSOLUE de la suite, que l'éditeur
       de liens a fixée en haut (un saut relatif resterait en bas). */
    movabs rax, offset haut
    jmp rax
haut:
    lea rsp, [rip + __pile_haut]
    mov rdi, r15
    call noyau_main
2:  cli
    hlt
    jmp 2b

    .section .bss.demarrage, "aw", @nobits
    .p2align 12
demarrage_pml4: .skip 4096
demarrage_pdpt_identite: .skip 4096
demarrage_pdpt_directe: .skip 4096
demarrage_pdpt_noyau: .skip 4096
demarrage_pd: .skip 4096
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
    let debut = &raw const _start as u64;
    afficherln!("[noyau] Mode long 64 bits, noyau a {:#x} (charge a {:#x}).", debut, espace::physique_du_noyau(debut));
    #[cfg(feature = "test-gros")]
    verifier_gros();

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
    let fin_noyau = espace::physique_du_noyau(&raw const __bss_fin as u64);
    match cadres::initialiser(fin_noyau) {
        Ok(bilan) => {
            afficherln!("[noyau] Memoire libre : {} cadres de 4 Kio ({} Mio).",
                        bilan.libres, bilan.libres as u64 * cadres::TAILLE_CADRE >> 20);
            afficherln!("        Carte de bits : {} Kio a {:#x}, apres le noyau (fin a {:#x}).",
                        bilan.taille_bits >> 10, bilan.adresse_bits, fin_noyau);
        }
        Err(e) => panic!("allocateur de cadres : {}", e),
    }

    // Les tables de pages définitives : jusqu'ici, seul le premier Gio est
    // projeté, sans protection.
    let bilan = pagination::initialiser();
    if bilan.nx {
        afficherln!("[noyau] Pagination W^X en place : noyau en {} pages de 4 Kio, {} Mio en projection directe.",
                    bilan.pages_noyau, bilan.projection_directe >> 20);
    } else {
        afficherln!("[noyau] Pagination en place, SANS le bit NX (absent du processeur) : les donnees restent executables.");
    }
    tester_cadres();

    // L'allocateur de démarrage cède la mémoire à l'allocateur de pages.
    let bilan = pages::initialiser();
    afficherln!("[noyau] Allocateur buddy : {} pages libres ({} Mio), blocs de 4 Kio a {} Mio ; etat des pages : {} Kio.",
                bilan.libres, bilan.libres >> 8, (4096 << pages::ORDRE_MAX) >> 20, bilan.taille_etats >> 10);
    tester_pages();
    tester_tas();

    // Le scénario de panne de `make tests-qemu` : déborder exprès de la
    // pile, que la page de garde doit arrêter net.
    #[cfg(feature = "test-garde")]
    {
        afficherln!("[noyau] Test : debordement volontaire de la pile.");
        deborder(0);
    }

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

    executer_bonjour();

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

/// Vérifie l'allocateur de pages : des blocs alignés sur leur taille, qu'on
/// peut écrire de bout en bout, et qui se recollent en les rendant (le
/// nombre de pages libres revient à ce qu'il était). Le plus grand bloc
/// possible : sur une très petite machine, il n'y a pas forcément de bloc
/// de 4 Mio.
fn tester_pages() {
    let libres_avant = pages::libres();
    let a = pages::allouer(0).expect("plus de memoire");
    let b = pages::allouer(3).expect("plus de memoire");
    let (c, ordre_c) = (0..=pages::ORDRE_MAX).rev().find_map(|o| pages::allouer(o).map(|c| (c, o))).expect("plus de memoire");
    let taille_c = 4096 << ordre_c;
    assert!(a % 4096 == 0 && b % (4096 << 3) == 0 && c % taille_c == 0);
    // SAFETY : `c` vient d'être alloué, il est à nous, de bout en bout.
    unsafe {
        let debut = espace::virtuelle(c) as *mut u8;
        debut.write_volatile(1);
        debut.add(taille_c as usize - 1).write_volatile(2);
    }
    pages::liberer(b, 3);
    pages::liberer(a, 0);
    pages::liberer(c, ordre_c);
    afficherln!("[noyau] Pages allouees : {:#x} (4 Kio), {:#x} (32 Kio), {:#x} ({} Kio) ; rendues et recollees : {}.",
                a, b, c, taille_c >> 10, if pages::libres() == libres_avant { "ok" } else { "ECHEC" });
}

/// Le premier programme WebAssembly : bonjour, compilé par rustc
/// (../bonjour), embarqué dans l'image du noyau. On le décode, le valide,
/// l'instancie avec WASI, puis on appelle son point d'entrée _start par
/// tranches de carburant : entre deux tranches, le noyau pourrait faire
/// autre chose (exécuter un autre programme). Les interruptions de
/// l'horloge et du clavier, elles, continuent d'arriver pendant tout ce
/// temps, même pendant une écriture du programme (la console écrit par
/// petits paquets).
fn executer_bonjour() {
    use alloc::sync::Arc;
    use wasm::{Etat, Externe, Magasin, Piege};

    static BONJOUR: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../bonjour/target/wasm32-unknown-unknown/release/bonjour.wasm"));
    const TRANCHE: u64 = 1000;

    let module = match wasm::decoder(BONJOUR).and_then(wasm::valider) {
        Ok(m) => Arc::new(m),
        Err(e) => return afficherln!("[noyau] Programme WebAssembly refuse : {}", e),
    };
    afficherln!("[noyau] Programme WebAssembly : {} octets, decode et valide.", BONJOUR.len());
    // Son budget de mémoire : 16 Mio pour ses tables et sa mémoire, chacune
    // d'au plus 4 Mio (un bloc du tas, voir tas.rs).
    let mut magasin = Magasin::avec_budget(16 << 20);
    let imports = match wasi::imports(&mut magasin, &module) {
        Ok(i) => i,
        Err(e) => return afficherln!("[noyau] Programme non liable : {}", e),
    };
    let instance = match magasin.instancier(module, &imports) {
        Ok(i) if i.demarrage.is_none() => i.instance,
        Ok(_) => return afficherln!("[noyau] Programme refuse : fonction de demarrage inattendue"),
        Err(e) => return afficherln!("[noyau] Programme non instanciable : {}", e),
    };
    let Some(Externe::Fonction(debut)) = magasin.exporte(instance, "_start") else {
        return afficherln!("[noyau] Programme sans _start");
    };
    // WASI veut un _start de type [] -> [] : un programme qui en attend des
    // arguments est refusé, comme le reste, sans que le noyau s'arrête.
    let Ok(mut execution) = magasin.preparer(debut, &[]) else {
        return afficherln!("[noyau] Programme refuse : _start doit etre de type [] -> []");
    };
    let (mut tranches, mut consomme) = (0u64, 0u64);
    let fin = loop {
        let mut carburant = TRANCHE;
        let etat = execution.reprendre(&mut magasin, &mut wasi::Wasi, &mut carburant);
        tranches += 1;
        consomme += TRANCHE - carburant;
        match etat {
            Ok(Etat::Interrompue) => continue,
            autre => break autre,
        }
    };
    let code = match fin {
        // proc_exit(code), ou _start qui revient sans l'appeler : code 0.
        Err(Piege::Hote(code)) => code,
        Ok(_) => 0,
        Err(p) => return afficherln!("[noyau] Programme arrete par un piege : {}", p),
    };
    afficherln!("[noyau] Programme termine : code de sortie {}, {} unites de carburant en {} tranches.",
                code, consomme, tranches);
}

/// Vérifie le tas : des collections de Rust de toutes tailles, et un objet
/// rendu qui sert à nouveau.
fn tester_tas() {
    use alloc::{boxed::Box, format, vec, vec::Vec};
    // Un Vec qui grandit : il passe par plusieurs classes, puis par des
    // pages (8000 octets à la fin).
    let carres: Vec<u64> = (0..1000).map(|i| i * i).collect();
    let somme: u64 = carres.iter().sum();
    let texte = format!("Vec de {} carres (somme {})", carres.len(), somme);
    let grand = vec![1u8; 1 << 20];
    // L'objet rendu doit être le prochain donné. black_box cache les
    // adresses à l'optimiseur : sans lui, le compilateur, qui sait que deux
    // allocations distinctes n'ont jamais la même adresse, remplace la
    // comparaison par « faux » sans l'exécuter.
    let a = Box::into_raw(Box::new(1u32));
    let adresse_a = core::hint::black_box(a as usize);
    // SAFETY : `a` vient de Box::into_raw, rendu une seule fois.
    drop(unsafe { Box::from_raw(a) });
    let b = Box::new(2u32);
    let reutilise = core::hint::black_box(&*b as *const u32 as usize) == adresse_a;
    afficherln!("[noyau] Tas : {}, Box, String, 1 Mio d'un bloc ({} octets a 1) : {}.",
                texte, grand.iter().filter(|&&o| o == 1).count(), if reutilise { "ok" } else { "ECHEC" });
}

/// Une récursion sans fin (ou presque : la condition, jamais vraie, évite
/// l'avertissement du compilateur). Chaque appel garde 512 octets sur la
/// pile ; black_box empêche le compilateur de les supprimer, ou de changer
/// la récursion en boucle.
#[cfg(feature = "test-garde")]
fn deborder(n: u64) -> u64 {
    if n == u64::MAX {
        return 0;
    }
    let tableau = core::hint::black_box([n; 64]);
    deborder(n + 1) + tableau[63]
}

/// Le scénario « noyau gonflé » de `make tests-qemu` : 1,5 Mio de
/// constantes, assez pour que l'image dépasse 1 Mio (l'ancienne limite du
/// tampon en mémoire basse était de 576 Kio). Le début de chaque secteur de
/// 512 octets porte son propre numéro : un morceau lu au mauvais endroit,
/// ou pas lu du tout (des zéros), se voit au premier secteur faux. Le
/// dernier octet du tableau, le dernier du fichier qui compte, vaut 0x5A.
#[cfg(feature = "test-gros")]
fn verifier_gros() {
    const TAILLE: usize = 3 << 19;
    const fn gros() -> [u8; TAILLE] {
        let mut t = [0u8; TAILLE];
        let mut secteur = 0;
        while secteur < TAILLE / 512 {
            let numero = (secteur as u64).to_le_bytes();
            let mut i = 0;
            while i < 8 {
                t[secteur * 512 + i] = numero[i];
                i += 1;
            }
            secteur += 1;
        }
        t[TAILLE - 1] = 0x5A;
        t
    }
    static GROS: [u8; TAILLE] = gros();
    // black_box : sans lui, le compilateur, qui connaît le contenu du
    // tableau, ferait la vérification lui-même et n'en garderait rien.
    let gros = core::hint::black_box(&GROS);
    let faux = (0..TAILLE / 512).find(|&s| gros[s * 512..s * 512 + 8] != (s as u64).to_le_bytes());
    match faux {
        None if gros[TAILLE - 1] == 0x5A => afficherln!(
            "[noyau] Test : noyau gonfle de {} Kio, chaque secteur a sa place : ok.", TAILLE >> 10),
        None => afficherln!("[noyau] Test : noyau gonfle, dernier octet faux : ECHEC."),
        Some(s) => afficherln!("[noyau] Test : noyau gonfle, secteur {} faux : ECHEC.", s),
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
    // On écrit dans un cadre, par la projection directe : il est bien
    // projeté et à nous.
    // SAFETY : `b` vient d'être alloué, personne d'autre ne s'en sert.
    unsafe { core::ptr::write_bytes(espace::virtuelle(b) as *mut u8, 0, cadres::TAILLE_CADRE as usize) };
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
