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
mod aleatoire;
mod appel_systeme;
mod appels_fichiers;
mod cadres;
mod carte_memoire;
mod chargeur_elf;
mod copie_utilisateur;
mod clavier;
mod cpu;
mod demarrage;
mod descripteurs;
mod espace;
mod espace_utilisateur;
mod evenements;
mod faute_de_page;
mod futex;
mod gdt;
mod horloge;
mod interruptions;
mod linux;
mod memoire;
mod pagination;
mod pile;
mod pages;
mod pic;
mod port;
mod procfs;
mod processus;
mod programmes;
mod serie;
mod signaux;
mod sse;
mod tache;
mod tas;
mod temps;
mod verrou;
mod vfs;
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
// Le chargeur passe l'adresse des informations de démarrage dans rdi ; or
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
extern "C" fn noyau_main(infos: u64) -> ! {
    console::initialiser();
    afficherln!("[noyau] Bonjour depuis le noyau Rust !");
    let debut = &raw const _start as u64;
    afficherln!("[noyau] Mode long 64 bits, noyau a {:#x} (charge a {:#x}).", debut, espace::physique_du_noyau(debut));
    #[cfg(feature = "test-gros")]
    verifier_gros();

    gdt::initialiser();
    interruptions::initialiser();
    appel_systeme::initialiser();
    afficherln!("[noyau] GDT, TSS et IDT du noyau en place ; syscall pret.");

    // Test volontaire : int3 déclenche l'exception 3. Si l'IDT est fausse,
    // c'est une triple faute et QEMU redémarre ; sinon, on revient ici.
    // SAFETY : int3 ne fait qu'appeler notre gestionnaire, qui revient.
    unsafe { asm!("int3") };
    afficherln!("[noyau] Retour apres int3 : les exceptions sont gerees.");

    // La mémoire physique : les informations du chargeur (dont la carte du
    // BIOS), puis l'allocateur de cadres.
    // SAFETY : `infos` est l'adresse passée par notre chargeur, et rien n'a
    // encore réutilisé la mémoire basse.
    if let Err(e) = unsafe { demarrage::recopier(infos) } {
        panic!("informations de demarrage illisibles ({})", e);
    }
    carte_memoire::afficher();
    let fin_noyau = espace::physique_du_noyau(&raw const __bss_fin as u64);
    match cadres::initialiser(fin_noyau, demarrage::archive()) {
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
    let p = copie_utilisateur::activer_protections();
    let oui_non = |b: bool| if b { "oui" } else { "non (absent du processeur)" };
    afficherln!("[noyau] Protections contre les programmes : SMEP {}, SMAP {}, UMIP {}.",
                oui_non(p.smep), oui_non(p.smap), oui_non(p.umip));
    afficherln!("[noyau] Alea des programmes (AT_RANDOM) : {}.", aleatoire::source());
    sse::initialiser();
    afficherln!("[noyau] SSE pour les programmes : FXSR, sans XSAVE (pas d'AVX).");

    // L'allocateur de démarrage cède la mémoire à l'allocateur de pages.
    let bilan = pages::initialiser();
    afficherln!("[noyau] Allocateur buddy : {} pages libres ({} Mio), blocs de 4 Kio a {} Mio ; descripteurs des cadres : {} Kio.",
                bilan.libres, bilan.libres >> 8, (4096 << pages::ORDRE_MAX) >> 20, bilan.taille_descripteurs >> 10);
    afficherln!("[noyau] Memoire des programmes : surengagement (OVERCOMMIT_GUESS), reserve du noyau de {} Kio.",
                bilan.reserve * 4);
    tester_pages();
    tester_tas();
    tester_espace_utilisateur();

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
    match temps::initialiser() {
        Some((annee, mois, jour, heure, minute, seconde)) => afficherln!(
            "[noyau] Heure (UTC) : {annee:04}-{mois:02}-{jour:02} {heure:02}:{minute:02}:{seconde:02}, de l'horloge CMOS."
        ),
        None => afficherln!("[noyau] Pas d'horloge CMOS lisible : la date part du 1er janvier 1970."),
    }

    match clavier::initialiser() {
        Ok(()) => afficherln!("[noyau] Clavier PS/2 pret : tapez du texte."),
        Err(()) => afficherln!("[noyau] Pas de controleur clavier 8042 qui reponde."),
    }

    programmes::demarrer();

    // Le scénario des programmes de test de `make tests-qemu` : une fois
    // l'archive exécutée, éteindre QEMU par son périphérique isa-debug-exit
    // (présent seulement si on le demande à QEMU, à ce port-là). Jamais
    // dans le noyau ordinaire : sur une vraie machine, ce port peut être
    // n'importe quoi.
    #[cfg(feature = "test-programmes")]
    {
        afficherln!("[noyau] Fin des tests : extinction de QEMU.");
        // SAFETY : le port 0xf4 est celui d'isa-debug-exit dans
        // `make tests-qemu` ; QEMU s'arrête aussitôt.
        unsafe { port::ecrire(0xf4, 0) };
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

/// Vérifie l'allocateur de pages : des blocs alignés sur leur taille, qu'on
/// peut écrire de bout en bout, et qui se recollent en les rendant (le
/// nombre de pages libres revient à ce qu'il était). Le plus grand bloc
/// possible : sur une très petite machine, il n'y a pas forcément de bloc
/// de 4 Mio. Une page prise deux fois n'est rendue qu'au second `lacher`.
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
    pages::prendre(a);
    let compteur = pages::references(a) == 2 && !pages::lacher(a) && pages::lacher(a);
    pages::liberer(b, 3);
    pages::liberer(c, ordre_c);
    afficherln!("[noyau] Pages allouees : {:#x} (4 Kio), {:#x} (32 Kio), {:#x} ({} Kio) ; prise deux fois, rendue au second lacher : {} ; rendues et recollees : {}.",
                a, b, c, taille_c >> 10, if compteur { "ok" } else { "ECHEC" },
                if pages::libres() == libres_avant { "ok" } else { "ECHEC" });
}

/// Vérifie l'espace d'adressage d'un programme : le créer, y projeter une
/// page, l'écrire par son adresse de programme, la relire par la projection
/// directe, puis tout détruire. Toutes les pages (la page, les quatre
/// tables) doivent revenir à l'allocateur, et les adresses interdites être
/// refusées.
fn tester_espace_utilisateur() {
    use espace_utilisateur::{EspaceUtilisateur, Erreur, ADRESSE_MAX, ADRESSE_MIN};
    const ADRESSE: u64 = 0x40_0000;
    let libres_avant = pages::libres();
    let mut e = EspaceUtilisateur::creer().expect("plus de memoire");
    let rw = zones::Droits { lecture: true, ecriture: true, execution: false };
    let r = zones::Droits { lecture: true, ..zones::Droits::AUCUN };
    let cadre = e.projeter_neuve(ADRESSE, rw).expect("plus de memoire");
    let refus = [
        e.projeter_neuve(ADRESSE, r) == Err(Erreur::DejaProjetee),
        e.projeter_neuve(0, r) == Err(Erreur::AdresseInterdite),
        e.projeter_neuve(ADRESSE_MIN - 4096, r) == Err(Erreur::AdresseInterdite),
        e.projeter_neuve(ADRESSE_MAX, r) == Err(Erreur::AdresseInterdite),
        e.projeter_neuve(ADRESSE + 1, r) == Err(Erreur::AdresseInterdite),
        e.traduire(ADRESSE).map(|(c, _)| c) == Some(cadre),
    ];
    // On écrit par l'adresse du programme, comme un appel système : par la
    // copie protégée (et SMAP doit refuser une lecture directe), puis on
    // relit par la projection directe du cadre.
    // SAFETY : l'espace a la moitié haute du noyau (pile, code) : on
    // continue de s'exécuter après avoir changé CR3 ; on revient sur la
    // PML4 du noyau avant de le détruire.
    unsafe { pagination::activer(e.pml4()) };
    let copie = copie_utilisateur::copier_vers_utilisateur(ADRESSE, &0x1234_5678u64.to_le_bytes());
    let hors_bornes = copie_utilisateur::copier_vers_utilisateur(ADRESSE_MAX - 4, &[0; 8]);
    let absente = copie_utilisateur::copier_vers_utilisateur(ADRESSE + 4096 - 4, &[0; 8]);
    let smap_ok = !copie_utilisateur::SMAP_ACTIF.load(core::sync::atomic::Ordering::Relaxed)
        || copie_utilisateur::smap_verifie(ADRESSE);
    // SAFETY : la PML4 du noyau est complète.
    unsafe { pagination::activer(pagination::pml4_noyau()) };
    // SAFETY : `cadre` est la page projetée, à nous jusqu'à la destruction
    // de l'espace.
    let relu = unsafe { (espace::virtuelle(cadre) as *const u64).read_volatile() };
    let refus = [refus.iter().all(|&r| r), copie.is_ok(), hors_bornes.is_err(), absente.is_err(), smap_ok];
    drop(e);
    let ok = relu == 0x1234_5678 && refus.iter().all(|&r| r) && pages::libres() == libres_avant;
    afficherln!("[noyau] Espace d'un programme : page {:#x} ecrite par son adresse (copie protegee), relue par le cadre {:#x} ; memoire rendue : {}.",
                ADRESSE, cadre, if ok { "ok" } else { "ECHEC" });
    if copie_utilisateur::SMAP_ACTIF.load(core::sync::atomic::Ordering::Relaxed) && smap_ok {
        afficherln!("[noyau] SMAP verifie : une lecture directe de la memoire d'un programme fait faute.");
    }
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
    // Mille objets de 100 octets (la classe de 128 : 32 par page), rendus :
    // les pages découpées pour eux reviennent à l'allocateur de pages. Le
    // tableau des boîtes (8000 octets) prend, lui, un bloc de pages, rendu
    // aussi.
    let libres = pages::libres();
    let boites: Vec<Box<[u8; 100]>> = (0..1000).map(|_| Box::new([7; 100])).collect();
    let prises = libres - pages::libres();
    drop(boites);
    let rendues = prises >= 1000 / 32 && pages::libres() == libres;
    afficherln!("[noyau] Tas : {}, Box, String, 1 Mio d'un bloc ({} octets a 1) : {} ; pages vides rendues : {}.",
                texte, grand.iter().filter(|&&o| o == 1).count(), if reutilise { "ok" } else { "ECHEC" },
                if rendues { "ok" } else { "ECHEC" });
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
