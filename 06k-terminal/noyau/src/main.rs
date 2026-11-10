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
#![deny(unsafe_code)]

// Les collections de Rust (Box, Vec, String), servies par notre tas (tas.rs).
extern crate alloc;

// Où `unsafe` est permis : seulement dans les modules d'abstraction de bas
// niveau, chacun avec #[allow(unsafe_code)], rangés ci-dessous par famille
// (comme la crate `kernel` de Rust pour Linux : `kernel::io`, `page`,
// `uaccess`, `sync`). Partout ailleurs, `#![deny(unsafe_code)]` le refuse :
// la logique (les appels système, les protocoles) passe par les fonctions
// sûres de ces modules. Chaque bloc `unsafe` dit pourquoi il est sûr (un
// commentaire SAFETY, exigé par clippy : Cargo.toml).
//
// La console d'abord : ses macros afficher! et afficherln! servent dans
// tous les modules. Elle force son verrou en cas de panique.
#[macro_use]
#[allow(unsafe_code)]
mod console;
// Les signaux d'entrée-sortie : le propriétaire d'un fichier, O_ASYNC.
mod asynchrone;

// Le matériel : les ports, la mémoire des périphériques (MMIO), l'assembleur
// (`asm!`), les registres et les tables du processeur, les tables du
// BIOS et de l'ACPI.
#[allow(unsafe_code)]
mod acpi;
#[allow(unsafe_code)]
mod aleatoire;
#[allow(unsafe_code)]
mod apic;
#[allow(unsafe_code)]
mod clavier;
#[allow(unsafe_code)]
mod cpu;
#[allow(unsafe_code)]
mod gdt;
#[allow(unsafe_code)]
mod horloge;
#[allow(unsafe_code)]
mod interruptions;
#[allow(unsafe_code)]
mod ioapic;
#[allow(unsafe_code)]
mod msix;
#[allow(unsafe_code)]
mod pci;
#[allow(unsafe_code)]
mod pic;
#[allow(unsafe_code)]
mod port;
#[allow(unsafe_code)]
mod processeur;
#[allow(unsafe_code)]
mod serie;
#[allow(unsafe_code)]
mod smp;
#[allow(unsafe_code)]
mod sse;
#[allow(unsafe_code)]
mod temps;
#[allow(unsafe_code)]
mod trampoline;
#[allow(unsafe_code)]
mod tsc;
#[allow(unsafe_code)]
mod vga;
#[allow(unsafe_code)]
mod virtio;
#[allow(unsafe_code)]
mod virtio_rng;
#[allow(unsafe_code)]
mod virtqueue;

// La mémoire physique, vue par la projection directe ; et le tas.
#[allow(unsafe_code)]
mod cadres;
#[allow(unsafe_code)]
mod demarrage;
#[allow(unsafe_code)]
mod espace_utilisateur;
#[allow(unsafe_code)]
mod faillible;
#[allow(unsafe_code)]
mod pages;
#[allow(unsafe_code)]
mod pagination;
#[allow(unsafe_code)]
mod tas;
// Les notes des grands blocs rendus, écrites dans leur premier cadre.
#[allow(unsafe_code)]
mod vmalloc;
// vfs.rs : les pages des fichiers, que le tmpfs désigne par leur numéro de
// cadre ; un type qui les possède les sortira d'ici, avec la couche VFS de
// 6m (« Reste à faire »).
#[allow(unsafe_code)]
mod vfs;

// Les copies vers et depuis les programmes (l'anneau 3).
#[allow(unsafe_code)]
mod copie_utilisateur;

// La synchronisation : les verrous, les files d'attente et leurs entrées
// liées (des listes intrusives), les valeurs partagées.
#[allow(unsafe_code)]
mod attente;
#[allow(unsafe_code)]
mod irq;
#[allow(unsafe_code)]
mod ordonnanceur;
// L'Arc faillible, dans la bibliothèque faillible/ (les soldes d'avant 6k) :
// son `unsafe` y est.
mod partage;
#[allow(unsafe_code)]
mod verrou;

// La bascule d'une tâche à l'autre, et l'entrée dans le noyau.
#[allow(unsafe_code)]
mod appel_systeme;
#[allow(unsafe_code)]
mod tache;

// Tout le reste : sans unsafe.
mod appels_fichiers;
mod appels_reseau;
mod cadre_signal;
mod carte_memoire;
mod chargeur_elf;
mod descripteurs;
mod epoll;
mod espace;
mod evenements;
mod faute_de_page;
mod fil;
mod futex;
mod linux;
mod memoire;
mod oom;
mod pile;
mod processus;
mod procfs;
mod programmes;
mod reprise;
mod reseau;
mod rusage;
mod signaux;
mod sondage;
mod surveillance;
mod sysfs;
mod tube;
mod wasi;

use core::arch::asm;
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
// noyau les remplacera par les siennes, page par page. Sauf la PDPT à
// l'identique et sa PD, qui restent (6j) : elles sont la moitié basse de
// la PML4 du trampoline des processeurs secondaires (trampoline.rs), qui
// démarrent eux aussi à une adresse basse et doivent y lire quelques
// instructions une fois leur pagination active ; d'où le symbole global.
//
// Une fois en haut, la base de GS du noyau reçoit l'adresse de la zone du
// premier processeur (processeur.rs, ZONES_PROCESSEURS) : le premier
// `Verrou` de noyau_main (celui de la console) compte déjà ses verrous
// tenus dans cette zone. C'est ce que fait `startup_64` pour le premier
// processeur de Linux (head_64.S : MSR_GS_BASE avant la première fonction
// C). Les processeurs secondaires (6j) font de même avec la leur.
//
// Le chargeur passe l'adresse des informations de démarrage dans rdi ; or
// rep stosb se sert de rdi : on la met de côté dans r15, puis on la rend à
// rdi, 1er argument de noyau_main.
//
// Ce fichier n'est pas un module d'abstraction, mais le démarrage touche
// le matériel et la mémoire physique avant que tout soit en place : son
// entrée, `noyau_main` et les auto-tests qui lisent la mémoire par ses
// adresses ont chacun leur #[allow(unsafe_code)].
#[allow(unsafe_code)]
mod entree {
    core::arch::global_asm!(
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
    lea rax, [rip + ZONES_PROCESSEURS]
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0000101
    wrmsr
    lea rsp, [rip + __pile_haut]
    mov rdi, r15
    call noyau_main
2:  cli
    hlt
    jmp 2b

    .section .bss.demarrage, "aw", @nobits
    .p2align 12
    .global demarrage_pdpt_identite
demarrage_pml4: .skip 4096
demarrage_pdpt_identite: .skip 4096
demarrage_pdpt_directe: .skip 4096
demarrage_pdpt_noyau: .skip 4096
demarrage_pd: .skip 4096
    "#
    );
}

#[allow(unsafe_code)]
unsafe extern "C" {
    // Défini dans le global_asm! ci-dessus : seule son adresse nous intéresse.
    static _start: u8;
    // Défini par le script d'édition de liens : la fin du noyau en mémoire
    // (après la .bss et la pile).
    static __bss_fin: u8;
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "C" fn noyau_main(infos: u64) -> ! {
    console::initialiser();
    afficherln!("[noyau] Bonjour depuis le noyau Rust !");
    let debut = &raw const _start as u64;
    afficherln!("[noyau] Mode long 64 bits, noyau a {:#x} (charge a {:#x}).", debut, espace::physique_du_noyau(debut));
    #[cfg(feature = "test-gros")]
    verifier_gros();

    // La GDT et la TSS du premier processeur, dans sa zone (processeur.rs,
    // que `_start` a mise dans GS) ; l'IDT, commune à tous ; `syscall`.
    gdt::initialiser(processeur::zone(0), gdt::piles_ist_du_premier());
    interruptions::initialiser();
    appel_systeme::initialiser();
    afficherln!("[noyau] Processeur 0 : GDT, TSS et IDT en place, sa zone dans GS ; syscall pret (swapgs) ; {} processeur en service.",
                processeur::nombre());
    if cpu::bogue_sysret_ss() {
        afficherln!("[noyau] Processeur AMD : SS recharge a chaque bascule, pour sysretq (X86_BUG_SYSRET_SS_ATTRS).");
    }

    // Test volontaire : int3 déclenche l'exception 3. Si l'IDT est fausse,
    // c'est une triple faute et QEMU redémarre ; sinon, on revient ici.
    // SAFETY: int3 ne fait qu'appeler notre gestionnaire, qui revient.
    unsafe { asm!("int3") };
    afficherln!("[noyau] Retour apres int3 : les exceptions sont gerees.");

    // La mémoire physique : les informations du chargeur (dont la carte du
    // BIOS), puis l'allocateur de cadres.
    // SAFETY: `infos` est l'adresse passée par notre chargeur, et rien n'a
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
    // Le générateur aléatoire : ce que donnent RDSEED et RDRAND, avant
    // les interruptions (le `random_init_early` de Linux).
    aleatoire::initialiser();
    // Les fonctions de la bibliothèque crypto rejouent un vecteur officiel
    // chacune, compilées pour le noyau (l'hôte n'a vérifié que leur
    // version pour lui) : le `blake2s_selftest` et ses semblables de Linux.
    afficherln!("[alea] ChaCha20, BLAKE2s, SipHash : vecteurs des RFC : {}.", if crypto::verifier() { "ok" } else { "ECHEC" });
    let fpu = sse::initialiser();
    if fpu.xsave {
        afficherln!("[noyau] SSE pour les programmes : XSAVE (x87, SSE{}), {} octets par tache.",
                    if fpu.avx { ", AVX" } else { "" }, fpu.taille);
    } else {
        afficherln!("[noyau] SSE pour les programmes : FXSAVE (x87, SSE, pas d'AVX), {} octets par tache.", fpu.taille);
    }

    // L'allocateur de démarrage cède la mémoire à l'allocateur de pages.
    let bilan = pages::initialiser();
    afficherln!("[noyau] Allocateur buddy : {} pages libres ({} Mio), blocs de 4 Kio a {} Mio ; descripteurs des cadres : {} Kio.",
                bilan.libres, bilan.libres >> 8, (4096 << pages::ORDRE_MAX) >> 20, bilan.taille_descripteurs >> 10);
    afficherln!("[noyau] Memoire des programmes : surengagement (OVERCOMMIT_GUESS), reserve du noyau de {} Kio.",
                bilan.reserve * 4);
    tester_pages();
    tester_tas();
    // La région des adresses à la demande : avant le premier espace
    // d'adressage, qui recopie la moitié haute de la PML4 du noyau.
    let bilan = vmalloc::initialiser();
    afficherln!("[noyau] Adresses du noyau a la demande (vmalloc) : {} piles de {} Kio sous leur page de garde, tables faites d'avance ({} Kio).",
                bilan.piles, vmalloc::TAILLE_PILE >> 10, bilan.tables >> 10);
    tester_vmalloc();
    tester_grands_blocs();
    // Le code en cours devient la tâche inactive (tache.rs) ; la file des
    // tâches prêtes, réservée pour autant de tâches que de piles.
    tache::initialiser();
    ordonnanceur::initialiser(vmalloc::max_threads());
    attente::initialiser(vmalloc::max_threads());
    processus::initialiser(vmalloc::max_threads());
    tester_espace_utilisateur();
    match acpi::initialiser() {
        Ok(()) => acpi::afficher(),
        Err(acpi::Absence::SansRsdp) => afficherln!("[noyau] Pas de tables ACPI (pas de RSDP dans la memoire du BIOS)."),
        Err(acpi::Absence::Racine(a, e)) => afficherln!("[noyau] Tables ACPI illisibles : la table racine a {:#x} : {}.", a, e),
    }

    // Le bus PCI : ce qui y est branché, et où sont ses registres. Avant
    // les interruptions : rien ne s'affiche pendant la mesure des BAR (la
    // carte VGA coupée), et aucun pilote ne s'en sert encore.
    let n = pci::initialiser();
    afficherln!("[pci] {} fonctions sur le bus (ports 0xCF8 et 0xCFC).", n);
    pci::afficher();

    // Les interruptions matérielles : d'abord le contrôleur (l'APIC et
    // l'IO-APIC, ou le 8259 ; tout masqué), puis l'horloge qui démasque son
    // IRQ, et seulement alors sti. Dans l'autre ordre, une IRQ pourrait
    // arriver sur un vecteur d'exception.
    let bilan = irq::initialiser();
    // Le TSC, étalonné contre le PIT avant que le PIT ne serve (ou ne soit
    // arrêté) ; puis le tic : le timer de l'APIC si l'APIC et le TSC le
    // permettent, le PIT sinon.
    let tsc = tsc::etalonner();
    let source = horloge::initialiser(irq::apic());
    cpu::activer_interruptions();
    match bilan {
        irq::Bilan::Apic { apic, ioapic } => {
            afficher!("[noyau] APIC local {} a {:#x} (xAPIC, version {:#x})", apic.id, apic.adresse, apic.version);
            for (n, adresse, gsi, entrees) in ioapic.ioapics {
                afficher!(", IO-APIC {} a {:#x} (GSI {}-{})", n, adresse, gsi, gsi + entrees - 1);
            }
            afficherln!(" ; 8259 masque.");
            afficherln!("[noyau] Clavier : IRQ {} sur le GSI {}, vecteur {:#x}.",
                        clavier::IRQ, ioapic::gsi(clavier::IRQ).unwrap_or(0), irq::vecteur(clavier::IRQ));
        }
        irq::Bilan::Pic(raison) => afficherln!("[noyau] PIC 8259 ({}) remappe sur les vecteurs {}-{}.",
                                               raison, pic::VECTEUR_BASE, pic::VECTEUR_BASE + pic::NB_IRQ - 1),
        irq::Bilan::PicSansApic(e) => afficherln!("[noyau] PIC 8259 ({}) remappe sur les vecteurs {}-{}.",
                                                  e, pic::VECTEUR_BASE, pic::VECTEUR_BASE + pic::NB_IRQ - 1),
    }
    match tsc {
        tsc::Bilan::Fiable { khz, essais } => afficherln!("[noyau] TSC : {}.{:03} MHz, constant ({} essais sur 5 retenus) : l'heure a la nanoseconde.",
                                                         khz / 1000, khz % 1000, essais),
        tsc::Bilan::NonConstant => afficherln!("[noyau] TSC non fiable (le processeur ne le dit pas constant) : l'heure au tic."),
        tsc::Bilan::Mesure => afficherln!("[noyau] TSC non fiable (mesures rejetees ou en desaccord) : l'heure au tic."),
    }
    match source {
        horloge::Source::Apic { hz, etalon } => afficherln!("[noyau] Horloge : timer de l'APIC ({}.{:03} MHz apres le diviseur, mesure contre le {}), {} Hz, vecteur {:#x} ; PIT arrete.",
                                                            hz / 1_000_000, hz / 1000 % 1000, etalon, horloge::HZ, apic::VECTEUR_TIMER),
        horloge::Source::Pit => afficherln!("[noyau] Horloge : PIT, {} Hz, vecteur {:#x}.", horloge::HZ, irq::vecteur(horloge::IRQ)),
    }
    // Les processeurs secondaires (smp.rs) : maintenant que l'APIC, l'horloge,
    // vmalloc et les tâches sont en place, et que les registres de contrôle
    // du premier ont leur valeur finale, qu'ils doivent reprendre.
    smp::demarrer_secondaires();
    // Le compte affiché est celui depuis le démarrage de l'horloge : 100,
    // plus les tics passés à écrire les messages qui précèdent (sous QEMU,
    // un ou deux par ligne, le port série étant un fichier), plus parfois
    // un tic tombé entre le réveil et la lecture du compteur.
    horloge::attendre_ms(100);
    afficherln!("[noyau] 100 ms plus tard : {} tics comptes.", horloge::tics());
    tester_vecteurs();
    tester_tlb();
    tester_remplacement();
    match temps::initialiser() {
        Some((annee, mois, jour, heure, minute, seconde)) => afficherln!(
            "[noyau] Heure (UTC) : {annee:04}-{mois:02}-{jour:02} {heure:02}:{minute:02}:{seconde:02}, de l'horloge CMOS."
        ),
        None => afficherln!("[noyau] Pas d'horloge CMOS lisible : la date part du 1er janvier 1970."),
    }
    // L'heure aussi distingue ce démarrage d'un autre : versée au
    // générateur, sans crédit (le `random_init` de Linux).
    aleatoire::melanger(&temps::maintenant().secondes.to_le_bytes());
    // La fréquence du TSC, affinée contre le PM timer de l'ACPI sur au
    // moins une seconde : le premier échantillon ici, le second avant le
    // premier programme (tsc.rs, `finir_affinage`).
    if let Some(port) = acpi::port_du_timer_pm() {
        tsc::commencer_affinage(port);
    }

    // Le scénario de panne de `make tests-qemu` : déborder exprès de la
    // pile, que la page de garde doit arrêter net. Dans une tâche du noyau,
    // sur sa pile de vmalloc : c'est la page de garde de chaque tâche qui
    // est vérifiée.
    #[cfg(feature = "test-garde")]
    {
        afficherln!("[noyau] Test : debordement volontaire de la pile d'une tache.");
        tache::lancer_noyau(programmes::NomCourt::de(b"test-garde"), || {
            deborder(0);
        });
    }

    // Le clavier, et sa tâche : elle dort jusqu'à ce qu'une touche soit
    // tapée, puis l'affiche.
    match clavier::initialiser() {
        Ok(()) => {
            tache::lancer_noyau(programmes::NomCourt::de(b"clavier"), clavier::tache);
            afficherln!("[noyau] Clavier PS/2 pret : tapez du texte.")
        }
        Err(()) => afficherln!("[noyau] Pas de controleur clavier 8042 qui reponde."),
    }

    // Le réseau : les cartes qu'on sait piloter, et la tâche qui fait leur
    // travail.
    // Le générateur matériel de la machine virtuelle, s'il y en a un :
    // avant le réseau, qui tire ses premiers nombres (le DHCP).
    virtio_rng::sonder();
    reseau::demarrer();

    afficherln!("[noyau] Ordonnanceur EEVDF : tranche de {}.{:02} ms, preemption du noyau.",
                ordonnanceur::TRANCHE / 1_000_000, ordonnanceur::TRANCHE / 10_000 % 100);
    // init : vérifie l'ordonnanceur, puis lance /etc/demarrage, dans sa
    // tâche.
    let init = || {
        // Les tests de l'ordonnanceur de 6e supposent que leurs tâches se
        // partagent UN processeur (la préemption ne se prouve pas sur
        // deux) : init s'épingle sur le processeur 0, ses tâches héritent
        // du masque, puis il le rend.
        let affinite = tache::courante().affinite();
        tache::courante().poser_affinite(1);
        ordonnanceur::affinite_changee(tache::courante());
        tester_ordonnanceur();
        tester_sommeil();
        tester_verrou_le();
        tache::courante().poser_affinite(affinite);
        ordonnanceur::affinite_changee(tache::courante());
        tester_parallele();
        tester_tourner();
        tester_torture();
        reseau::configurer();
        tester_voisins();
        reseau::autotest::lancer();
        match tsc::finir_affinage() {
            Some(tsc::Affinage::Fait { khz, avant }) => afficherln!(
                "[noyau] TSC affine contre le PM timer de l'ACPI : {}.{:03} MHz ({} ppm de la premiere mesure).",
                khz / 1000, khz % 1000, (khz as i64 - avant as i64) * 1_000_000 / avant as i64),
            Some(tsc::Affinage::Rejete { khz, avant }) => afficherln!(
                "[noyau] TSC : l'affinage donne {}.{:03} MHz, a plus de 1 % des {}.{:03} mesures : garde.",
                khz / 1000, khz % 1000, avant / 1000, avant % 1000),
            Some(tsc::Affinage::Abandonne) => afficherln!("[noyau] TSC : pas d'affinage (le TSC ne sert plus, ou le PM timer ne bouge pas)."),
            None => {}
        }
        programmes::demarrer();
        if cpu::bogue_sysret_ss() {
            afficherln!("[noyau] Processeur AMD : SS recharge a {} bascules, pour sysretq.", cpu::ss_recharges());
        }
        // Le scénario des programmes de test de `make tests-qemu` : une
        // fois l'archive exécutée, éteindre QEMU par son périphérique
        // isa-debug-exit (présent seulement si on le demande à QEMU, à ce
        // port-là). Jamais dans le noyau ordinaire : sur une vraie
        // machine, ce port peut être n'importe quoi.
        #[cfg(feature = "test-programmes")]
        {
            afficherln!("[noyau] Fin des tests : extinction de QEMU.");
            // SAFETY: le port 0xf4 est celui d'isa-debug-exit dans
            // `make tests-qemu` ; QEMU s'arrête aussitôt.
            unsafe { port::ecrire(0xf4, 0) };
        }
    };
    // Le rendeur des piles des tâches mortes (tache.rs), avant toute tâche
    // qui puisse mourir.
    tache::lancer_rendeur();
    if tache::lancer_noyau(programmes::NomCourt::de(b"init"), init).is_none() {
        afficherln!("[noyau] Pas de pile pour la tache init : rien a lancer.");
    }

    // Le code du démarrage est maintenant la tâche inactive du processeur
    // 0 : sa boucle (ordonnanceur.rs) prend le processeur quand aucune
    // autre tâche n'est prête, tire du travail des autres files, regarde si
    // des programmes ne sont pas bloqués pour toujours
    // (attente::detecter_interblocage), et arrête le processeur (sti ; hlt)
    // jusqu'à la prochaine interruption.
    ordonnanceur::boucle_inactive()
}

/// Vérifie l'ordonnanceur et la préemption du noyau : deux tâches du noyau
/// qui calculent chacune 20 ms, sans jamais céder d'elles-mêmes, doivent se
/// partager le processeur : chacune voit le compteur de l'autre avancer
/// pendant son propre calcul, ce qui n'arrive que si le tic l'a préemptée.
fn tester_ordonnanceur() {
    use core::sync::atomic::AtomicU64;
    static COMPTEURS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
    static VU: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];
    let calculer = |moi: usize| {
        move || {
            let autre_au_debut = COMPTEURS[1 - moi].load(Ordering::Relaxed);
            let debut = tache::temps_de_calcul();
            while tache::temps_de_calcul() - debut < 20_000_000 {
                COMPTEURS[moi].fetch_add(1, Ordering::Relaxed);
                if COMPTEURS[1 - moi].load(Ordering::Relaxed) != autre_au_debut {
                    VU[moi].store(true, Ordering::Relaxed);
                }
            }
        }
    };
    let bascules = ordonnanceur::bascules();
    let a = tache::lancer_noyau(programmes::NomCourt::de(b"calcul-a"), calculer(0));
    let b = tache::lancer_noyau(programmes::NomCourt::de(b"calcul-b"), calculer(1));
    if let (Some(a), Some(b)) = (&a, &b) {
        tache::attendre(a);
        tache::attendre(b);
    }
    let ok = a.is_some() && b.is_some() && VU.iter().all(|v| v.load(Ordering::Relaxed));
    afficherln!("[noyau] Ordonnanceur : deux taches du noyau qui calculent 20 ms chacune se partagent le processeur : {} ({} bascules).",
                if ok { "ok" } else { "ECHEC" }, ordonnanceur::bascules() - bascules);

    // Le compte de préemption (processeur.rs) : une tâche qui calcule 10 ms
    // préemption coupée ne doit pas être remplacée (le compteur d'une
    // autre, prête, ne bouge pas : sur un seul processeur, l'autre n'a pas
    // d'autre moyen de s'exécuter ; avec plusieurs, les deux sont
    // épinglées sur le même, 6j), puis l'est dès qu'elle la rétablit :
    // sur-le-champ, avant son pas suivant (le point de préemption de
    // `retablir_preemption`, 6j). Le tic, lui, passe encore (il compte le
    // temps de calcul qui sert ici).
    static TEMOIN: AtomicU64 = AtomicU64::new(0);
    static FINI: AtomicBool = AtomicBool::new(false);
    static RESULTAT: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];
    let c = tache::lancer_noyau(programmes::NomCourt::de(b"calcul-c"), || {
        let calculer_10_ms = || {
            let debut = tache::temps_de_calcul();
            while tache::temps_de_calcul() - debut < 10_000_000 {
                core::hint::spin_loop();
            }
        };
        let avant = TEMOIN.load(Ordering::Relaxed);
        // Le témoin est lu AVANT de rétablir la préemption : la rétablir
        // cède le processeur sur-le-champ, et D aurait déjà bougé le témoin.
        let pendant = processeur::sans_preemption(|| {
            calculer_10_ms();
            TEMOIN.load(Ordering::Relaxed)
        });
        RESULTAT[0].store(pendant == avant, Ordering::Relaxed);
        // Dès qu'elle la rétablit : D, dont le tour est venu depuis
        // longtemps, s'est exécutée avant que C ne fasse ce pas-ci.
        RESULTAT[1].store(TEMOIN.load(Ordering::Relaxed) != avant, Ordering::Relaxed);
        FINI.store(true, Ordering::Relaxed);
    });
    let d = tache::lancer_noyau(programmes::NomCourt::de(b"calcul-d"), || {
        while !FINI.load(Ordering::Relaxed) {
            TEMOIN.fetch_add(1, Ordering::Relaxed);
        }
    });
    if let (Some(c), Some(d)) = (&c, &d) {
        tache::attendre(c);
        tache::attendre(d);
    }
    let ok = c.is_some() && d.is_some() && RESULTAT.iter().all(|r| r.load(Ordering::Relaxed));
    afficherln!("[noyau] Preemption coupee : une tache qui calcule 10 ms n'est pas remplacee, puis l'est des qu'elle la retablit : {}.",
                if ok { "ok" } else { "ECHEC" });

    // Préempter en rendant un verrou (6j, verrou.rs) : une tâche dont le
    // « besoin de céder » a été levé pendant qu'elle tenait un Verrou cède
    // dès qu'elle le rend, pas au tic suivant (le `preempt_enable` du
    // `spin_unlock` de Linux). Le lever sous un Verrou sans dépendre d'un
    // choix de l'EEVDF (un réveil ne passe devant la courante que si elle
    // n'est plus protégée, ce qui dépend de l'instant) : la tâche
    // s'interdit son propre processeur, ce que fait un fil qui se déplace
    // par sched_setaffinity (ordonnanceur.rs, l'affinité) ; le verrou
    // rendu, elle doit déjà s'exécuter ailleurs (le processeur 1, inactif,
    // la tire à son prochain tic). Deux processeurs au moins.
    if processeur::nombre() >= 2 {
        static VERROU: verrou::Verrou<()> = verrou::Verrou::new(());
        static APRES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
        let e = tache::lancer_noyau(programmes::NomCourt::de(b"migre-verrou"), || {
            let t = tache::courante();
            let garde = VERROU.verrouiller();
            t.poser_affinite(1 << 1);
            ordonnanceur::affinite_changee(t);
            drop(garde);
            APRES.store(processeur::sans_preemption(|| processeur::courant().numero), Ordering::Relaxed);
        });
        if let Some(e) = &e {
            tache::attendre(e);
        }
        afficherln!("[noyau] Preemption en rendant un verrou : une tache qui doit ceder cede des qu'elle rend son verrou, pas au tic suivant : {}.",
                    if e.is_some() && APRES.load(Ordering::Relaxed) == 1 { "ok" } else { "ECHEC" });
    } else {
        afficherln!("[noyau] Preemption en rendant un verrou : un seul processeur, rien a deplacer.");
    }
}

/// Vérifie que les processeurs travaillent ensemble (6j) : quatre tâches du
/// noyau qui calculent 50 ms chacune finissent en moins de 150 ms quand il
/// y a au moins deux processeurs (200 au moins l'une après l'autre) ; sur
/// un seul, la durée est seulement dite.
fn tester_parallele() {
    let n = processeur::nombre();
    let debut = temps::ns_monotone();
    let calculer = || {
        let debut = tache::temps_de_calcul();
        while tache::temps_de_calcul() - debut < 50_000_000 {
            core::hint::spin_loop();
        }
    };
    let taches = [
        tache::lancer_noyau(programmes::NomCourt::de(b"parallele-1"), calculer),
        tache::lancer_noyau(programmes::NomCourt::de(b"parallele-2"), calculer),
        tache::lancer_noyau(programmes::NomCourt::de(b"parallele-3"), calculer),
        tache::lancer_noyau(programmes::NomCourt::de(b"parallele-4"), calculer),
    ];
    for t in taches.iter().flatten() {
        tache::attendre(t);
    }
    let ms = (temps::ns_monotone() - debut) / 1_000_000;
    let lancees = taches.iter().all(Option::is_some);
    if n >= 2 {
        afficherln!("[noyau] Parallele : quatre taches de 50 ms sur {} processeurs finies en {} ms : {}.", n, ms,
                    if lancees && ms < 150 { "ok" } else { "ECHEC" });
    } else {
        afficherln!("[noyau] Parallele : quatre taches de 50 ms sur un processeur finies en {} ms{}.", ms, if lancees { "" } else { " : ECHEC" });
    }
}

/// Dort `ms` millisecondes (pour les tests).
fn dormir_ms(ms: u64) {
    let interruptions = cpu::couper_interruptions();
    tache::courante().preparer_sommeil(attente::Sommeil::Ininterruptible);
    attente::dormir(Some(temps::ns_monotone() + ms * 1_000_000), attente::Sommeil::Ininterruptible);
    tache::courante().reveille();
    if interruptions {
        cpu::activer_interruptions();
    }
}

/// Vérifie « tourner d'abord » (attente.rs, 6j) : une tâche du processeur
/// 1 tient un verrou qui dort 15 µs en calculant (moins que la borne du
/// tour) ; une tâche du processeur 0 le demande pendant ce temps et
/// l'obtient en tournant, sans dormir. Vingt parties, dont au moins une
/// gagnée ainsi (sous QEMU, une interruption au mauvais moment fait manquer
/// les 15 µs : voir plus bas). Puis le détenteur dort 2 ms en le tenant :
/// la demandeuse s'endort (on ne tourne pas sur un détenteur qui ne
/// s'exécute pas). Un Mutex, puis un VerrouLE tenu et demandé en écriture
/// (un lecteur, lui, ne tourne pas : attente.rs). Les compteurs sont ceux
/// de tous les verrous qui dorment : personne d'autre n'en dispute un
/// pendant ce test (init attend, les programmes ne sont pas lancés). Deux
/// processeurs au moins.
fn tester_tourner() {
    if processeur::nombre() < 2 {
        afficherln!("[noyau] Verrous qui dorment : un seul processeur, pas de tour a verifier.");
        return;
    }
    static M: attente::Mutex<()> = attente::Mutex::new(());
    static V: attente::VerrouLE<()> = attente::VerrouLE::new(());
    static TENU: AtomicBool = AtomicBool::new(false);
    static PRETE: AtomicBool = AtomicBool::new(false);
    /// Le détenteur : sur le processeur 1, attend que la demandeuse soit en
    /// place (elle doit demander PENDANT qu'il tient : les deux se
    /// déplacent au rythme des tics), prend, le dit, garde le verrou en
    /// calculant ou en dormant, le rend.
    fn tenir<G>(prendre: impl FnOnce() -> G, dort: bool) {
        aller_sur(1);
        while !PRETE.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let garde = prendre();
        TENU.store(true, Ordering::Release);
        if dort {
            dormir_ms(2);
        } else {
            horloge::attendre_us(15);
        }
        drop(garde);
    }
    /// La demandeuse : sur le processeur 0, attend que le détenteur tienne
    /// le verrou, puis le demande.
    fn demander<G>(prendre: impl FnOnce() -> G) {
        aller_sur(0);
        PRETE.store(true, Ordering::Release);
        while !TENU.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        drop(prendre());
    }
    // Une partie : (prises en tournant, sommeils) ; None si une tâche n'a
    // pu être lancée.
    let jouer = |detenteur: fn(), demandeuse: fn()| -> Option<(u64, u64)> {
        TENU.store(false, Ordering::Relaxed);
        PRETE.store(false, Ordering::Relaxed);
        attente::compteurs_des_verrous_qui_dorment();
        let d = tache::lancer_noyau(programmes::NomCourt::de(b"detenteur"), detenteur);
        let q = tache::lancer_noyau(programmes::NomCourt::de(b"demandeuse"), demandeuse);
        for t in [&d, &q].into_iter().flatten() {
            tache::attendre(t);
        }
        (d.is_some() && q.is_some()).then(attente::compteurs_des_verrous_qui_dorment)
    };
    // Le détenteur qui calcule : vingt parties, dont au moins une prise en
    // tournant. Sous QEMU, une interruption (un tic : des dizaines de µs)
    // entre « il tient » et le tour, ou pendant le tour, fait manquer les
    // 15 µs du détenteur ou dépasser la borne du tour, et la demandeuse
    // trouve le verrou libre (0/0) ou dort (0/1) : le hasard des
    // interruptions, pas le mécanisme, qu'une partie sur vingt suffit à
    // montrer (mesuré : une partie unique échouait un démarrage sur dix).
    const PARTIES: u32 = 20;
    let compter = |detenteur: fn(), demandeuse: fn()| -> Option<u32> {
        let mut prises = 0;
        for _ in 0..PARTIES {
            if jouer(detenteur, demandeuse)? == (1, 0) {
                prises += 1;
            }
        }
        Some(prises)
    };
    let mutex_tours = compter(|| tenir(|| M.verrouiller(), false), || demander(|| M.verrouiller()));
    let mutex_dort = jouer(|| tenir(|| M.verrouiller(), true), || demander(|| M.verrouiller()));
    let le_tours = compter(|| tenir(|| V.ecrire(), false), || demander(|| V.ecrire()));
    let le_dort = jouer(|| tenir(|| V.ecrire(), true), || demander(|| V.ecrire()));
    // Sans TSC fiable (-cpu qemu64), l'heure est au tic : les 15 µs du
    // détenteur et la borne du tour finissent au même tic, et la demandeuse
    // trouve toujours le verrou libre sans avoir tourné ni dormi (0/0).
    // Seules les parties où il dort se vérifient alors.
    let heure_fine = tsc::khz().is_some();
    let dort = |r: Option<(u64, u64)>| r == Some((0, 1));
    let tourne = |n: Option<u32>| n.is_some_and(|n| n >= 1);
    let ok = dort(mutex_dort) && dort(le_dort) && (!heure_fine || (tourne(mutex_tours) && tourne(le_tours)));
    let (md, ld) = (mutex_dort.unwrap_or((9, 9)), le_dort.unwrap_or((9, 9)));
    afficherln!("[noyau] Verrous qui dorment : pris en tournant quand le detenteur calcule ailleurs, en dormant quand il dort : {} (Mutex {} prises en tournant sur {} parties, puis {}/{} ; VerrouLE {} sur {}, puis {}/{}{}).",
                if ok { "ok" } else { "ECHEC" }, mutex_tours.unwrap_or(0), PARTIES, md.0, md.1, le_tours.unwrap_or(0), PARTIES, ld.0, ld.1,
                if heure_fine { "" } else { " ; heure au tic : le tour s'arrete au tic, non verifie" });
}

/// Vérifie le protocole de sommeil (attente.rs, tache.rs) : « je vais
/// dormir » posé, une tâche PRÉEMPTÉE (elle calcule 5 ms, le tic la
/// remplace) ne quitte pas la file des prêtes, trouve ensuite sa condition
/// vraie et ne dort pas ; et une tâche RÉVEILLÉE entre « je vais dormir »
/// et son sommeil (par une autre, d'un autre processeur quand il y en a
/// un, pendant qu'elle attend ce réveil sans dormir) voit son `dormir`
/// revenir tout de suite, avec la raison. Les deux pannes que le protocole
/// exclut : une tâche perdue, un réveil perdu.
fn tester_sommeil() {
    static CONDITION: AtomicBool = AtomicBool::new(false);
    static RESULTAT: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];
    /// L'éveilleuse a réveillé la dormeuse (REVEILLEE : `reveiller` l'a
    /// trouvée endormie), puis l'a dit (REVEIL_FAIT).
    static REVEILLEE: AtomicBool = AtomicBool::new(false);
    static REVEIL_FAIT: AtomicBool = AtomicBool::new(false);
    let dormeuse = tache::lancer_noyau(programmes::NomCourt::de(b"dormeuse"), || {
        let t = tache::courante();
        // 1. Préemptée entre « je vais dormir » et la condition.
        t.preparer_sommeil(attente::Sommeil::Ininterruptible);
        let debut = tache::temps_de_calcul();
        while tache::temps_de_calcul() - debut < 5_000_000 {
            core::hint::spin_loop();
        }
        // Toujours là : la préemption ne l'a pas retirée de la file.
        RESULTAT[0].store(true, Ordering::Relaxed);
        t.reveille();
        // 2. Réveillée AVANT de dormir : elle pose l'état, puis attend, sans
        // dormir, que l'éveilleuse ait posé la condition et l'ait réveillée
        // (REVEIL_FAIT, écrit après `reveiller`) ; son `dormir` doit alors
        // revenir sans dormir, avec la raison. (Jusqu'à la relecture de 6j,
        // elle cédait le processeur et l'EEVDF pouvait la rechoisir avant
        // l'éveilleuse : elle dormait pour de bon, et le test passait sans
        // rien prouver.)
        t.preparer_sommeil(attente::Sommeil::Ininterruptible);
        while !REVEIL_FAIT.load(Ordering::Acquire) {
            // Sur un seul processeur, l'éveilleuse a besoin du nôtre : une
            // préemption, l'état posé reste.
            ordonnanceur::ceder();
        }
        let interruptions = cpu::couper_interruptions();
        let r = attente::dormir(None, attente::Sommeil::Ininterruptible);
        if interruptions {
            cpu::activer_interruptions();
        }
        RESULTAT[1].store(r == tache::Reveil::Reveillee && CONDITION.load(Ordering::Relaxed) && REVEILLEE.load(Ordering::Relaxed), Ordering::Relaxed);
        t.reveille();
    });
    let eveilleuse = dormeuse.clone().and_then(|d| {
        tache::lancer_noyau(programmes::NomCourt::de(b"eveilleuse"), move || {
            // D'un autre processeur quand il y en a un : un vrai réveil
            // croisé. Attend que la dormeuse ait posé son second « je vais
            // dormir », puis la réveille, et le dit.
            if processeur::nombre() >= 2 {
                aller_sur(1);
            }
            while !RESULTAT[0].load(Ordering::Relaxed) || d.sommeil_non_prepare() {
                ordonnanceur::ceder();
            }
            CONDITION.store(true, Ordering::Relaxed);
            REVEILLEE.store(tache::reveiller(d, tache::Reveil::Reveillee), Ordering::Relaxed);
            REVEIL_FAIT.store(true, Ordering::Release);
        })
    });
    if let (Some(d), Some(e)) = (&dormeuse, &eveilleuse) {
        tache::attendre(d);
        tache::attendre(e);
    }
    let ok = dormeuse.is_some() && eveilleuse.is_some() && RESULTAT.iter().all(|r| r.load(Ordering::Relaxed));
    afficherln!("[noyau] Sommeil : une tache preemptee entre \"je vais dormir\" et sa condition n'est pas perdue, un reveil venu avant son sommeil n'est pas perdu : {}.",
                if ok { "ok" } else { "ECHEC" });
}

/// Vérifie le verrou qui dort en lecture et en écriture (attente.rs,
/// `VerrouLE`) par des tâches du noyau, dont chacune note ce qu'elle fait
/// dans un journal, une lettre par pas ; l'ordre de leurs arrivées est
/// forcé (chacune n'est lancée qu'une fois la précédente rangée dans la
/// file), ce qui rend le journal attendu exact :
///   1. un écrivain (E) tient le verrou ; arrivent un lecteur (L), un
///      écrivain (F), un lecteur ; à sa libération (e), les deux lecteurs
///      passent ENSEMBLE (chacun attend l'autre avant de rendre le verrou),
///      le second devant l'écrivain qui attendait avant lui (la phase des
///      lecteurs), puis l'écrivain : « EeLLllFf » ;
///   2. un lecteur (M) tient le verrou ; arrive un écrivain (G), puis un
///      lecteur (N), qui doit se ranger derrière l'écrivain au lieu
///      d'entrer avec M (sinon l'écrivain pourrait attendre sans fin) ;
///      l'écrivain passe, puis rétrograde (D) : le lecteur entre pendant
///      qu'il lit encore. L'écrivain attend de le voir entré pour rendre le
///      verrou (d), et le lecteur, de le voir rendu (n) : « MmGDNdn ».
fn tester_verrou_le() {
    use core::sync::atomic::{AtomicU8, AtomicUsize};
    static V: attente::VerrouLE<()> = attente::VerrouLE::new(());
    static JOURNAL: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];
    static PAS: AtomicUsize = AtomicUsize::new(0);
    static RENDRE: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];
    // Le lecteur N est entré ; l'écrivain rétrogradé a rendu le verrou.
    static ENTRE: AtomicBool = AtomicBool::new(false);
    static RENDU: AtomicBool = AtomicBool::new(false);
    fn noter(lettre: u8) {
        // AcqRel : « j'ai fait ce pas » est publié à la tâche que le test
        // lance ensuite (après `attendre_que(PAS == n)`, en Acquire) : le
        // journal prétend prouver un ordre, l'ordre mémoire doit le tenir.
        let i = PAS.fetch_add(1, Ordering::AcqRel);
        if let Some(j) = JOURNAL.get(i) {
            j.store(lettre, Ordering::Relaxed);
        }
    }
    // Attend (une seconde au plus) que `vrai` le devienne.
    fn attendre_que(vrai: impl Fn() -> bool) -> bool {
        (0..1000).any(|_| {
            if vrai() {
                return true;
            }
            dormir_ms(1);
            false
        })
    }
    // Un lecteur de la phase 1 : il attend que l'autre soit entré aussi
    // avant de rendre le verrou (ce qui n'arrive que s'ils le tiennent
    // ensemble ; sinon l'attente finit au bout d'une seconde, et le journal
    // le montre).
    fn lecteur() {
        static DEDANS: AtomicUsize = AtomicUsize::new(0);
        let g = V.lire();
        noter(b'L');
        DEDANS.fetch_add(1, Ordering::AcqRel);
        attendre_que(|| DEDANS.load(Ordering::Acquire) == 2);
        noter(b'l');
        drop(g);
    }
    // Les tâches lancées, pour les attendre à la fin.
    let mut taches: [Option<partage::Arc<tache::Tache>>; 7] = Default::default();
    let mut lancees = taches.iter_mut();
    let mut lancer = |nom: &[u8], f: fn()| {
        let t = tache::lancer_noyau(programmes::NomCourt::de(nom), f);
        let ok = t.is_some();
        if let Some(place) = lancees.next() {
            *place = t;
        }
        ok
    };
    let mut ok = true;
    // 1. La phase des lecteurs.
    ok &= lancer(b"verrou-e", || {
        let g = V.ecrire();
        noter(b'E');
        attendre_que(|| RENDRE[0].load(Ordering::Relaxed));
        noter(b'e');
        drop(g);
    });
    ok &= attendre_que(|| PAS.load(Ordering::Acquire) == 1);
    ok &= lancer(b"verrou-l1", lecteur);
    ok &= attendre_que(|| V.en_attente() == 1);
    ok &= lancer(b"verrou-f", || {
        let g = V.ecrire();
        noter(b'F');
        // Remis par les lecteurs (`passer_la_main`) : personne n'entre
        // tant qu'il le tient. La file est vide : seul l'état du verrou peut
        // refuser (un « ! » au journal sinon).
        if V.essayer_lire().is_some() || V.essayer_ecrire().is_some() {
            noter(b'!');
        }
        noter(b'f');
        drop(g);
    });
    ok &= attendre_que(|| V.en_attente() == 2);
    ok &= lancer(b"verrou-l2", lecteur);
    ok &= attendre_que(|| V.en_attente() == 3);
    RENDRE[0].store(true, Ordering::Relaxed);
    ok &= attendre_que(|| PAS.load(Ordering::Acquire) == 8);
    // 2. Un lecteur ne passe pas devant un écrivain qui attend ; la
    // rétrogradation.
    ok &= lancer(b"verrou-m", || {
        let g = V.lire();
        noter(b'M');
        attendre_que(|| RENDRE[1].load(Ordering::Relaxed));
        noter(b'm');
        drop(g);
    });
    ok &= attendre_que(|| PAS.load(Ordering::Acquire) == 9);
    ok &= lancer(b"verrou-g", || {
        let g = V.ecrire();
        noter(b'G');
        // Rétrograder réveille N, et rendre le verrou de l'état cède le
        // processeur sur-le-champ si N passe devant G (6j, verrou.rs) : N
        // noterait sa lettre avant celle-ci. Préemption coupée le temps de
        // noter : le journal garde un ordre fixe (N passe à la fin du bloc,
        // ou au premier sommeil de G).
        let g = processeur::sans_preemption(|| {
            let g = g.retrograder();
            noter(b'D');
            g
        });
        attendre_que(|| ENTRE.load(Ordering::Acquire));
        noter(b'd');
        RENDU.store(true, Ordering::Release);
        drop(g);
    });
    ok &= attendre_que(|| V.en_attente() == 1);
    ok &= lancer(b"verrou-n", || {
        let g = V.lire();
        noter(b'N');
        ENTRE.store(true, Ordering::Release);
        attendre_que(|| RENDU.load(Ordering::Acquire));
        noter(b'n');
        drop(g);
    });
    // Rangé derrière l'écrivain, et pas entré avec M ; sans dormir non plus
    // (le `down_read_trylock` de Linux refuse aussi, un écrivain attend),
    // ni en écriture.
    ok &= attendre_que(|| V.en_attente() == 2);
    ok &= V.essayer_lire().is_none() && V.essayer_ecrire().is_none();
    RENDRE[1].store(true, Ordering::Relaxed);
    drop(lancer);
    for t in taches.iter().flatten() {
        tache::attendre(t);
    }
    // Libre : pris sans dormir, en écriture puis en lecture (chaque garde
    // rendue à la fin de sa ligne).
    let libre_en_ecriture = V.essayer_ecrire().is_some();
    let libre_en_lecture = V.essayer_lire().is_some();
    ok &= libre_en_ecriture && libre_en_lecture;
    let mut lu = [0u8; 15];
    for (l, j) in lu.iter_mut().zip(&JOURNAL) {
        *l = j.load(Ordering::Relaxed);
    }
    ok &= &lu == b"EeLLllFfMmGDNdn" && PAS.load(Ordering::Acquire) == 15;
    afficherln!("[noyau] Verrou qui dort en lecture et ecriture : les lecteurs passent ensemble, un ecrivain qui attend n'est pas double, retrogradation : {} ({}).",
                if ok { "ok" } else { "ECHEC" }, core::str::from_utf8(&lu).unwrap_or("?"));
}

/// Vérifie ARP et la table des voisins, une fois le réseau configuré : un
/// paquet IPv4 (vide, du protocole 253, « pour les essais », RFC 3692) pour
/// la passerelle et un pour le serveur DNS ; chacun attend la résolution de
/// son voisin (une requête en diffusion, la réponse de slirp par
/// l'interruption de réception), puis part. Dans le noyau des tests, une
/// adresse muette du réseau (10.0.2.99) : trois requêtes, l'échec au bout
/// de trois secondes, et son paquet jeté. Sans adresse : rien.
fn tester_voisins() {
    use reseau::arp;
    use inet::voisins::Etat;
    let (Some(i), Some(b)) = (reseau::interface::premiere_carte(), reseau::dhcp::bail()) else { return };
    let paquet = |destination: [u8; 4]| {
        let mut p = reseau::paquet::Paquet::vide(formats::reseau::ipv4::ENTETE)?;
        let e: &mut [u8; formats::reseau::ipv4::ENTETE] = p.ajouter_fin(formats::reseau::ipv4::ENTETE)?.try_into().ok()?;
        formats::reseau::ipv4::ecrire(e, &formats::reseau::ipv4::Ipv4 {
            tos: 0, longueur: 20, identifiant: 0, ne_pas_fragmenter: true, fragments_suivants: false, decalage: 0,
            ttl: 64, protocole: 253, source: b.adresse, destination, longueur_entete: 20,
        });
        Some(p)
    };
    let attendre = |adresse: [u8; 4], fini: fn(Etat) -> bool, ms: u64| {
        let debut = temps::ns_monotone();
        while !arp::voisin(i, adresse).is_some_and(|(e, _)| fini(e)) && temps::ns_monotone() - debut < ms * 1_000_000 {
            let interruptions = cpu::couper_interruptions();
            tache::courante().preparer_sommeil(attente::Sommeil::Ininterruptible);
            attente::dormir(Some(temps::ns_monotone() + 10_000_000), attente::Sommeil::Ininterruptible);
            tache::courante().reveille();
            if interruptions {
                cpu::activer_interruptions();
            }
        }
        ((temps::ns_monotone() - debut) / 1_000_000, arp::voisin(i, adresse))
    };
    let mut cibles = [b.passerelle, b.dns[0]];
    if cibles[0] == cibles[1] {
        cibles[1] = None;
    }
    let mut ok = true;
    for a in cibles.into_iter().flatten() {
        let Some(p) = paquet(a) else { return };
        arp::envoyer(i, a, p, false);
        let (_, v) = attendre(a, |e| e == Etat::Joignable, 1000);
        match v {
            Some((Etat::Joignable, mac)) => afficherln!("[reseau] {} : voisin {} : {}, joignable (ARP).", i.nom,
                                                       formats::reseau::Ipv4Affichee(a), reseau::virtio_net::Mac(mac)),
            _ => ok = false,
        }
    }
    afficherln!("[reseau] {} : la passerelle et le DNS resolus par ARP : {}.", i.nom, if ok { "ok" } else { "ECHEC" });
    #[cfg(feature = "test-programmes")]
    {
        let muet = [10, 0, 2, 99];
        let jetes = arp::jetes();
        let Some(p) = paquet(muet) else { return };
        arp::envoyer(i, muet, p, false);
        let (ms, v) = attendre(muet, |e| e == Etat::Echec, 5000);
        let echec = v.is_some_and(|(e, _)| e == Etat::Echec) && (2900..4000).contains(&ms);
        afficherln!("[reseau] {} : voisin muet 10.0.2.99 : echec apres trois requetes, en 3 s, son paquet jete : {}.", i.nom,
                    if echec && arp::jetes() == jetes + 1 { "ok" } else { "ECHEC" });
    }
}

/// Vérifie l'allocateur de pages : des blocs alignés sur leur taille, qu'on
/// peut écrire de bout en bout, et qui se recollent en les rendant (le
/// nombre de pages libres revient à ce qu'il était). Le plus grand bloc
/// possible : sur une très petite machine, il n'y a pas forcément de bloc
/// de 4 Mio. Une page prise deux fois n'est rendue qu'au second `lacher`.
#[allow(unsafe_code)]
fn tester_pages() {
    let libres_avant = pages::libres();
    let a = pages::allouer(0).expect("plus de memoire");
    let b = pages::allouer(3).expect("plus de memoire");
    let (c, ordre_c) = (0..=pages::ORDRE_MAX).rev().find_map(|o| pages::allouer(o).map(|c| (c, o))).expect("plus de memoire");
    let taille_c = 4096 << ordre_c;
    assert!(a % 4096 == 0 && b % (4096 << 3) == 0 && c % taille_c == 0);
    // SAFETY: `c` vient d'être alloué, il est à nous, de bout en bout.
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
#[allow(unsafe_code)]
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
    // SAFETY: l'espace a la moitié haute du noyau (pile, code) : on
    // continue de s'exécuter après avoir changé CR3 ; on revient sur la
    // PML4 du noyau avant de le détruire.
    unsafe { pagination::activer(e.pml4()) };
    let copie = copie_utilisateur::copier_vers_utilisateur(ADRESSE, &0x1234_5678u64.to_le_bytes());
    let hors_bornes = copie_utilisateur::copier_vers_utilisateur(ADRESSE_MAX - 4, &[0; 8]);
    let absente = copie_utilisateur::copier_vers_utilisateur(ADRESSE + 4096 - 4, &[0; 8]);
    let smap_ok = !copie_utilisateur::SMAP_ACTIF.load(core::sync::atomic::Ordering::Relaxed)
        || copie_utilisateur::smap_verifie(ADRESSE);
    // SAFETY: la PML4 du noyau est complète.
    unsafe { pagination::activer(pagination::pml4_noyau()) };
    // SAFETY: `cadre` est la page projetée, à nous jusqu'à la destruction
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

/// Vérifie la région des adresses à la demande : une pile, écrite par son
/// adresse et relue par la projection directe de ses cadres, sa garde sans
/// projection, puis rendue (toute la mémoire revient) ; et la mémoire
/// vidéo (dans le premier Mio, déjà vue par la projection directe)
/// projetée une seconde fois sans cache, comme des registres : les deux
/// vues lisent le même caractère.
#[allow(unsafe_code)]
fn tester_vmalloc() {
    let libres_avant = pages::libres();
    let pml4 = pagination::pml4_noyau();
    let Some(pile) = vmalloc::Pile::allouer() else {
        return afficherln!("[noyau] vmalloc : pas de pile : ECHEC.");
    };
    let (bas, haut) = (pile.bas(), pile.haut());
    // SAFETY: la pile vient d'être projetée, elle est à nous ; ses deux
    // bouts sont dans ses pages.
    unsafe {
        (bas as *mut u64).write_volatile(0x1234);
        ((haut - 8) as *mut u64).write_volatile(0x5678);
    }
    let relu = |v: u64| {
        pagination::traduire(pml4, v / 4096 * 4096)
            // SAFETY: un cadre de la pile, vu par la projection directe.
            .map(|c| unsafe { (espace::virtuelle(c + v % 4096) as *const u64).read_volatile() })
    };
    let ecrite = relu(bas) == Some(0x1234) && relu(haut - 8) == Some(0x5678);
    let garde = pagination::traduire(pml4, bas - 4096).is_none() && pagination::garde_touchee(bas - 1).is_some()
        && pagination::garde_touchee(bas).is_none();
    drop(pile);
    let rendue = pages::libres() == libres_avant && pagination::traduire(pml4, bas).is_none();
    // La mémoire vidéo en mode texte : 0xB8000, un caractère et sa
    // couleur par mot.
    let video = vmalloc::ioremap(0xB8000, 4096).map(|p| {
        // SAFETY: la page projetée est la mémoire vidéo, comme sa vue par
        // la projection directe ; lire un mot ne change rien.
        unsafe { (p.adresse() as *const u16).read_volatile() == (espace::virtuelle(0xB8000) as *const u16).read_volatile() }
    }) == Some(true);
    // Le BIOS (0xF0000, dans le premier Mio), projeté comme une table du
    // micrologiciel ; une page de la mémoire vive donnée à l'allocateur,
    // refusée.
    let bios = vmalloc::memremap(0xF0000 + 0x10, 8).map(|p| {
        // SAFETY: une page du BIOS, vue aussi par la projection directe.
        unsafe { (p.adresse() as *const u64).read_volatile() == (espace::virtuelle(0xF0010) as *const u64).read_volatile() }
    }) == Some(true);
    let vive = pages::allouer(0).map(|c| {
        let refusee = vmalloc::memremap(c, 8).is_none();
        pages::liberer(c, 0);
        refusee
    }) == Some(true);
    // Une adresse au-delà de MAXPHYADDR : refusée, pour des registres comme
    // pour une table (vmalloc::projeter).
    let bits = cpu::bits_physiques();
    let au_dela = vmalloc::ioremap(1 << bits, 8).is_none() && vmalloc::memremap(1 << bits, 8).is_none();
    let ok = |b: bool| if b { "ok" } else { "ECHEC" };
    afficherln!("[noyau] vmalloc : pile ecrite par son adresse, relue par la projection directe : {} ; garde sans projection : {} ; rendue : {} ; memoire video projetee sans cache : {} ; BIOS projete en lecture seule : {}, memoire vive refusee : {} ; au-dela des {} bits d'adresse physique, refusee : {}.",
                ok(ecrite), ok(garde), ok(rendue), ok(video), ok(bios), ok(vive), bits, ok(au_dela));
}

/// Vérifie les grands blocs du tas (vmalloc.rs, les soldes d'avant 6k) : un
/// Vec de 6 Mio, plus que le plus grand bloc d'un seul tenant de
/// l'allocateur de pages (4 Mio), est dans la région des adresses à la
/// demande, écrit à ses deux bouts, relu par la projection directe de ses
/// cadres, et suivi de sa garde. Rendu, il reste projeté jusqu'au passage
/// du rendeur (`purger`, ici à la main : aucune tâche n'existe encore),
/// puis toute sa mémoire revient. Puis trois pages prises directement par
/// vmalloc::allouer (le secours du tas quand la mémoire est morcelée), et
/// un alignement de plus d'une page, refusé.
#[allow(clippy::disallowed_macros, unsafe_code)]
fn tester_grands_blocs() {
    use alloc::vec;
    const TAILLE: usize = 6 << 20;
    let pml4 = pagination::pml4_noyau();
    let libres = || pages::libres() + vmalloc::tables_gardees();
    let avant = libres();
    let relu = |v: u64| {
        pagination::traduire(pml4, v / 4096 * 4096)
            // SAFETY: un cadre d'un bloc à nous, vu par la projection
            // directe.
            .map(|c| unsafe { (espace::virtuelle(c + v % 4096) as *const u8).read_volatile() })
    };
    let grand = vec![3u8; TAILLE];
    let debut = grand.as_ptr() as u64;
    let ecrit = vmalloc::contient(debut) && relu(debut) == Some(3) && relu(debut + TAILLE as u64 - 1) == Some(3);
    let garde = pagination::traduire(pml4, debut + TAILLE as u64).is_none();
    drop(grand);
    let differe = vmalloc::en_attente() == 1 && pagination::traduire(pml4, debut).is_some();
    vmalloc::purger();
    let rendu = vmalloc::en_attente() == 0 && pagination::traduire(pml4, debut).is_none() && libres() == avant;
    let p = vmalloc::allouer(3 * 4096 - 100, 8) as u64;
    let petit = p != 0 && relu(p + 2 * 4096).is_some() && pagination::traduire(pml4, p + 3 * 4096).is_none();
    if p != 0 {
        // SAFETY: le bloc vient d'allouer, avec cette taille ; personne ne
        // s'en sert.
        unsafe { vmalloc::rendre(p, 3 * 4096 - 100) };
    }
    vmalloc::purger();
    let petit = petit && libres() == avant;
    let aligne = vmalloc::allouer(4096, 8192).is_null();
    let ok = |b: bool| if b { "ok" } else { "ECHEC" };
    afficherln!("[noyau] vmalloc : un Vec de 6 Mio en pages eparses, ecrit et relu : {} ; sa garde : {} ; rendu apres le vidage des TLB, pas avant : {}, {} ; 3 pages : {} ; alignement de 8 Kio refuse : {}.",
                ok(ecrit), ok(garde), ok(differe), ok(rendu), ok(petit), ok(aligne));
}

/// Vérifie les vecteurs donnés à la demande : un vecteur donné, une IPI à
/// soi-même sur lui arrive à son gestionnaire (avec son argument), puis il
/// est rendu ; puis MSI-X : la table de la première carte virtio qui en a
/// une, mise en service, une entrée programmée puis relue, et rendue (la
/// table masquée, MSI-X coupé, la projection rendue). Sans APIC (le 8259
/// de repli), ni l'un ni l'autre : on le dit.
fn tester_vecteurs() {
    use core::sync::atomic::AtomicUsize;
    static RECU: AtomicUsize = AtomicUsize::new(0);
    fn gestionnaire(argument: usize) {
        RECU.store(argument, Ordering::Relaxed);
    }
    let ok = |b: bool| if b { "ok" } else { "ECHEC" };
    let libres = irq::libres();
    match irq::allouer(gestionnaire, 0x6789) {
        Some(v) => {
            apic::ipi_a_soi(v);
            // Elle arrive dès que le processeur l'accepte (les
            // interruptions sont permises) : sous QEMU sans accélération,
            // entre deux blocs traduits ; dix tics au plus.
            let debut = horloge::tics();
            while RECU.load(Ordering::Relaxed) == 0 && horloge::tics() - debut < 10 {
                core::hint::spin_loop();
            }
            let recu = RECU.load(Ordering::Relaxed) == 0x6789;
            irq::liberer(v);
            afficherln!("[noyau] Vecteurs a la demande : {:#x} donne, IPI a soi-meme recue par son gestionnaire : {} ; rendu : {}.",
                        v, ok(recu), ok(irq::libres() == libres));
        }
        None => afficherln!("[noyau] Vecteurs a la demande : pas d'APIC local, pas de vecteur."),
    }
    // Les interruptions entre processeurs (6j) : une IPI à chaque autre
    // processeur, sur un vecteur donné, reçue par lui (il note son numéro) ;
    // puis un appel de fonction à tous les autres (smp::appeler), qui
    // attend leurs réponses.
    if processeur::nombre() > 1 {
        use core::sync::atomic::{AtomicU32, AtomicU64};
        static RECUS: AtomicU64 = AtomicU64::new(0);
        static REPONSES: AtomicU32 = AtomicU32::new(0);
        fn noter(_: usize) {
            RECUS.fetch_or(1 << processeur::courant().numero, Ordering::Relaxed);
        }
        fn repondre(_: usize) {
            REPONSES.fetch_add(1, Ordering::Relaxed);
        }
        let autres = processeur::masque_en_service() & !1;
        if let Some(v) = irq::allouer(noter, 0) {
            for n in 1..processeur::MAX {
                if autres >> n & 1 != 0 {
                    apic::ipi(processeur::zone(n).apic.load(Ordering::Relaxed), v);
                }
            }
            let debut = horloge::tics();
            while RECUS.load(Ordering::Relaxed) != autres && horloge::tics() - debut < 10 {
                core::hint::spin_loop();
            }
            irq::liberer(v);
            smp::appeler_les_autres(repondre, 0);
            afficherln!("[noyau] IPI : chaque autre processeur a recu la sienne : {} ; un appel de fonction aux {} autres, tous repondent : {}.",
                        ok(RECUS.load(Ordering::Relaxed) == autres), processeur::nombre() - 1,
                        ok(REPONSES.load(Ordering::Relaxed) as usize == processeur::nombre() - 1));
        }
    }
    let carte = pci::fonctions().iter()
        .find(|f| f.entete.vendeur == 0x1af4 && f.capacites().any(|(_, n)| n == formats::pci::CAPACITE_MSIX));
    if let Some(f) = carte {
        match msix::MsiX::activer(f) {
            Ok(m) => {
                let programme = m.programmer(1, 0x45);
                let attendu = (0xfee0_0000 | (apic::id_du_premier() as u64) << 12, 0x45, false);
                afficherln!("[noyau] MSI-X de {} : {} entrees, entree 1 programmee et relue : {}.",
                            f.adresse, m.entrees(), ok(programme && m.message(1) == Some(attendu)));
            }
            Err(e) => afficherln!("[noyau] MSI-X de {} : {}.", f.adresse, e),
        }
    }
}

/// Vérifie le vidage des TLB entre processeurs (6j, espace_utilisateur.rs) :
/// un espace dont on fait croire que tous les processeurs en service l'ont
/// chargé (son masque), une page projetée puis retirée : le lot demande le
/// vidage aux autres processeurs, et chacun l'a reçu (son compte d'appels
/// reçus a monté : d'au moins un, un autre appel peut tomber en même
/// temps). Puis deux retraits en cours : le lot du premier, rempli et PAS
/// vidé, pendant qu'un second retrait de la même page ne trouve rien ; il
/// doit quand même demander le vidage aux autres (`MasqueProcesseurs::
/// retraits`). Le mécanisme seul : les secondaires ignorent une PML4 qu'ils
/// n'ont pas chargée.
fn tester_tlb() {
    use espace_utilisateur::{EspaceUtilisateur, Lot};
    if processeur::nombre() < 2 {
        return;
    }
    let ok = |b: bool| if b { "ok" } else { "ECHEC" };
    let autres = processeur::masque_en_service() & !1;
    let recus = || -> [u32; processeur::MAX] { core::array::from_fn(|n| processeur::zone(n).appels_recus.load(Ordering::Relaxed)) };
    let chacun_a_recu = |avant: &[u32; processeur::MAX]| {
        (1..processeur::MAX).filter(|&n| autres >> n & 1 != 0).all(|n| processeur::zone(n).appels_recus.load(Ordering::Relaxed) >= avant[n] + 1)
    };
    let rw = zones::Droits { lecture: true, ecriture: true, execution: false };
    let e = verrou::Verrou::new(EspaceUtilisateur::creer().expect("plus de memoire"));
    let page = 0x40_0000;
    // 1. Une page retirée.
    let avant = recus();
    e.verrouiller().projeter_neuve(page, rw).expect("plus de memoire");
    e.verrouiller().processeurs().processeurs.store(processeur::masque_en_service(), Ordering::Relaxed);
    let mut lot = Lot::new(&e.verrouiller());
    e.verrouiller().retirer_plage(page, page + 4096, true, &mut lot);
    lot.vider();
    let simple = chacun_a_recu(&avant);
    // 2. Deux retraits en cours.
    e.verrouiller().projeter_neuve(page, rw).expect("plus de memoire");
    let avant = recus();
    let mut premier = Lot::new(&e.verrouiller());
    e.verrouiller().processeurs().retraits.fetch_add(1, Ordering::SeqCst);
    e.verrouiller().retirer_plage(page, page + 4096, false, &mut premier);
    EspaceUtilisateur::retirer_par_tranches(&e, page, page + 4096, false, 0);
    let emboite = chacun_a_recu(&avant);
    e.verrouiller().processeurs().retraits.fetch_sub(1, Ordering::SeqCst);
    premier.vider();
    e.verrouiller().processeurs().processeurs.store(0, Ordering::Relaxed);
    drop(e);
    afficherln!("[noyau] TLB : une page retiree d'un espace que {} processeurs ont charge : vidage demande aux {} autres, recu par chacun : {} ; un second retrait pendant qu'un premier n'a pas vide : vidage demande quand meme : {}.",
                processeur::nombre(), processeur::nombre() - 1, ok(simple), ok(emboite));
}

/// Vérifie la marque de la copie à l'écriture (6j, espace_utilisateur.rs,
/// `jeton_de_marque`) : A écrit une page lue (la page de zéros) et pose sa
/// marque ; un madvise la retire ; B relit ; C écrit et pose la sienne.
/// Quand A revient finir, `remplacer` doit refuser (la marque n'est plus
/// la sienne) ; C, lui, finit. Un seul processeur suffit : c'est un ABA,
/// pas une course.
fn tester_remplacement() {
    use espace_utilisateur::{EspaceUtilisateur, Lot, Servi};
    let rw = zones::Droits { lecture: true, ecriture: true, execution: false };
    let mut e = EspaceUtilisateur::creer().expect("plus de memoire");
    let page = 0x50_0000;
    let mut rien = None;
    let lu = matches!(e.servir(page, rw, false, false, &mut rien), Ok(Servi::Fait));
    let mut page_a = espace_utilisateur::cadre_neuf();
    let Ok(Servi::Remplacement(mut lot_a, marque_a)) = e.servir(page, rw, true, false, &mut page_a) else {
        afficherln!("[noyau] Copie a l'ecriture : la premiere ecriture ne pose pas de marque : ECHEC.");
        return;
    };
    // Le madvise : la marque retirée, comme une page.
    let mut lot = Lot::new(&e);
    e.retirer_plage(page, page + 4096, false, &mut lot);
    lot.vider();
    let relu = matches!(e.servir(page, rw, false, false, &mut rien), Ok(Servi::Fait));
    let mut page_c = espace_utilisateur::cadre_neuf();
    let Ok(Servi::Remplacement(mut lot_c, marque_c)) = e.servir(page, rw, true, false, &mut page_c) else {
        afficherln!("[noyau] Copie a l'ecriture : la seconde ecriture ne pose pas de marque : ECHEC.");
        return;
    };
    lot_a.vider();
    let a_refuse = matches!(e.remplacer(page, rw, &mut page_a, marque_a), Ok(Servi::ARefaire)) && page_a.is_some();
    lot_c.vider();
    let c_finit = matches!(e.remplacer(page, rw, &mut page_c, marque_c), Ok(Servi::Fait)) && page_c.is_none();
    if let Some(c) = page_a {
        espace_utilisateur::rendre_cadre(c);
    }
    drop(e);
    afficherln!("[noyau] Copie a l'ecriture : une marque retiree par madvise puis reposee par un autre fil n'est pas prise pour la sienne : {}.",
                if lu && relu && marque_a != marque_c && a_refuse && c_finit { "ok" } else { "ECHEC" });
}

/// Se met sur le processeur `n` (ordonnanceur.rs : la tâche cède en
/// rétablissant la préemption, le processeur `n` la tire à son prochain
/// tic, elle revient ici sur lui). Pour les tests.
fn aller_sur(n: u32) {
    // Un processeur qui n'est pas en service (le scénario test-retard en
    // abandonne un) : la tâche reste où elle veut.
    if processeur::masque_en_service() >> n & 1 == 0 {
        return;
    }
    let t = tache::courante();
    t.poser_affinite(1 << n);
    ordonnanceur::affinite_changee(t);
}

/// Les tests de torture du plan de 6j : un `Verrou` disputé par une tâche
/// par processeur (100 000 prises chacune : le compte doit être exact), un
/// `Mutex` que deux tâches de deux processeurs se repassent, et des réveils
/// croisés (les tâches en anneau se passent un tour par une file d'attente :
/// un réveil perdu laisserait l'anneau à l'arrêt, un réveil doublé
/// mettrait une tâche deux fois en file, ce que `File::ajouter` refuse).
/// Chaque attente est bornée : un réveil perdu se voit en dix secondes au
/// lieu de figer le démarrage.
fn tester_torture() {
    const PAR_TACHE: u64 = 100_000;
    const PAR_MUTEX: u64 = 10_000;
    const TOURS: u64 = 2_000;
    static VERROU: verrou::Verrou<u64> = verrou::Verrou::new(0);
    static MUTEX: attente::Mutex<u64> = attente::Mutex::new(0);
    static TOUR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static FILE: attente::FileAttente = attente::FileAttente::new();
    static PERDUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    type Taches = [Option<partage::Arc<tache::Tache>>; 4];
    let n = processeur::nombre().min(4) as u64;
    if n < 2 {
        afficherln!("[noyau] Torture : un seul processeur, rien a disputer.");
        return;
    }
    // `combien` tâches, la i-ième sur le processeur i, qui font `travail(i)`.
    let lancer = |nom: &[u8], combien: u64, travail: fn(u64)| -> Taches {
        core::array::from_fn(|i| {
            let i = i as u64;
            (i < combien).then(|| tache::lancer_noyau(programmes::NomCourt::de(nom), move || travail(i))).flatten()
        })
    };
    let attendre_toutes = |taches: &Taches, combien: u64| -> bool {
        let lancees = &taches[..combien as usize];
        for t in lancees.iter().flatten() {
            tache::attendre(t);
        }
        lancees.iter().all(Option::is_some)
    };
    // 1. Le Verrou.
    let taches = lancer(b"torture-verrou", n, |i| {
        aller_sur(i as u32);
        for _ in 0..PAR_TACHE {
            *VERROU.verrouiller() += 1;
        }
    });
    let verrou_ok = attendre_toutes(&taches, n) && *VERROU.verrouiller() == n * PAR_TACHE;
    // 2. Le Mutex.
    let taches = lancer(b"torture-mutex", 2, |i| {
        aller_sur(i as u32);
        for _ in 0..PAR_MUTEX {
            *MUTEX.verrouiller() += 1;
        }
    });
    let mutex_ok = attendre_toutes(&taches, 2) && *MUTEX.verrouiller() == 2 * PAR_MUTEX;
    // 3. Les réveils croisés.
    static N: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    N.store(n, Ordering::Relaxed);
    let taches = lancer(b"torture-reveil", n, |i| {
        aller_sur(i as u32);
        let n = N.load(Ordering::Relaxed);
        for _ in 0..TOURS {
            let echeance = temps::ns_monotone() + 10_000_000_000;
            let r = attente::attendre_que(&FILE, attente::Inscription::Ordinaire, attente::Sommeil::Ininterruptible, Some(echeance),
                                          || TOUR.load(Ordering::SeqCst) % n == i);
            if r == tache::Reveil::Echeance {
                PERDUS.fetch_add(1, Ordering::Relaxed);
                return;
            }
            TOUR.fetch_add(1, Ordering::SeqCst);
            FILE.reveiller_toutes();
        }
    });
    let reveils_ok = attendre_toutes(&taches, n) && TOUR.load(Ordering::SeqCst) == n * TOURS && PERDUS.load(Ordering::Relaxed) == 0;
    afficherln!("[noyau] Torture : {} taches sur {} processeurs, {} prises d'un Verrou chacune ({}) ; un Mutex repasse {} fois ({}) ; {} reveils croises, aucun perdu ({}).",
                n, n, PAR_TACHE, if verrou_ok { "ok" } else { "ECHEC" }, 2 * PAR_MUTEX, if mutex_ok { "ok" } else { "ECHEC" },
                n * TOURS, if reveils_ok { "ok" } else { "ECHEC" });
}

/// Vérifie le tas : des collections de Rust de toutes tailles, et un objet
/// rendu qui sert à nouveau. Exprès avec les allocations ordinaires de
/// `alloc` (Box::new, vec!, format!, collect), celles que clippy.toml
/// refuse ailleurs : c'est elles qu'on essaie, au démarrage, où un échec
/// est l'échec du test.
#[allow(clippy::disallowed_methods, clippy::disallowed_macros, unsafe_code)]
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
    // SAFETY: `a` vient de Box::into_raw, rendu une seule fois.
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
#[allow(unsafe_code)]
fn tester_cadres() {
    let libres_avant = cadres::libres();
    let a = cadres::allouer().expect("plus de memoire");
    let b = cadres::allouer().expect("plus de memoire");
    let c = cadres::allouer().expect("plus de memoire");
    assert!(a != b && b != c && a != c && (a | b | c) % cadres::TAILLE_CADRE == 0);
    // On écrit dans un cadre, par la projection directe : il est bien
    // projeté et à nous.
    // SAFETY: `b` vient d'être alloué, personne d'autre ne s'en sert.
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
    // Qui panique, qui se tait, et la panique dans la panique : console.rs
    // (`preparer_panique`, un seul mot pour tous les processeurs).
    console::preparer_panique();
    afficherln!("[noyau] PANIQUE : {}", info);
    cpu::arreter()
}
