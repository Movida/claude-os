# Historique des échanges et des décisions

Ce fichier reprend la conversation de départ du projet (24 octobre 2026), pour qu'une nouvelle conversation puisse repartir exactement d'où on s'est arrêtés. Le contexte de travail au quotidien est dans `CLAUDE.md`.

## 1. Point de départ

**Question initiale :** existe-t-il un projet git proposant un noyau Linux minimal avec Claude Code dessus ?

**Réponse :** pas de projet de référence officiel. Projets voisins trouvés à l'époque :

- **JumpDev OS** (github.com/danupsher/jumpdev-os) : distribution live sur clé USB avec Claude Code préinstallé, mais pas minimaliste (bureau Hyprland, Docker, Neovim, Firefox).
- **claude-vm** (github.com/shudza/claude-vm) : sandbox en Bash au-dessus de QEMU, image Debian 13 « slim », nécessite KVM.
- **clawk** (github.com/clawkwork/clawk) : une VM jetable par dépôt, avec son propre noyau ; surtout macOS, Linux via Firecracker encore expérimental.
- **sbx** (github.com/aryanmehrotra/sbx) : une microVM Firecracker par sandbox.
- **awesome-agent-sandbox** (github.com/fishman/awesome-agent-sandbox) : panorama comparatif.

**Constat clé :** un noyau seul ne suffit pas. Claude Code a aussi besoin d'une libc, de certificats TLS et du réseau. Alpine Linux 3.19+ est officiellement supportée (dépôt apk signé), c'était la voie « assemblage » la plus légère.

## 2. Le chemin des décisions

1. **Objectif :** un noyau minimal, pas une simple sandbox.
2. **Cible :** du vrai matériel, mais utilisable aussi en VM. (Piste Linux évoquée à ce moment : un seul noyau, pilotes virtio intégrés, pilotes matériels en modules, `make localmodconfig`.)
3. **Écrire chaque brique soi-même, sans s'appuyer sur l'existant.** Mise en garde : réimplémenter l'interface de Linux, une pile réseau, TLS et des pilotes est un travail énorme. Un compromis a été proposé (garder le noyau Linux, écrire tout le reste), mais David a confirmé vouloir partir de zéro.
4. **Motivation :** apprendre comment tout fonctionne, au niveau le plus bas possible. Progression proposée, toujours testée sous QEMU avant le vrai matériel :
   1. chargeur de démarrage qui affiche du texte ;
   2. mémoire, interruptions, clavier ;
   3. processus et appels système ;
   4. pilote réseau virtio, puis petite pile TCP/IP.

   Ressources : le wiki OSDev (wiki.osdev.org) et « Writing an OS in Rust » de Philipp Oppermann (os.phil-opp.com).
5. **Langage :** C, Rust, Zig, assembleur pur, C++ et Ada ont été évoqués. Recommandation : le C, parce que presque toute la documentation OSDev est en C. Tranché le 24 octobre 2026 : **Rust** (voir la section 9).
6. **Compatibilité :** elle dépend des interfaces respectées, pas du langage (l'interface binaire du C, les appels système de Linux). Piste évoquée : **WebAssembly + WASI**, un noyau qui embarque un moteur Wasm et fait tourner tous les programmes dedans (exemple historique : le projet expérimental Nebulet). David trouve cette piste très intéressante.
7. **Problème :** Claude Code est un binaire natif x86_64, pas du WebAssembly. Deux options : une couche de compatibilité Linux dans le noyau, ou un agent maison qui appelle l'API Claude.
8. David préférait l'agent maison, **mais veut utiliser son abonnement Claude**. Or l'abonnement est réservé aux applications officielles comme Claude Code : un agent maison qui s'y connecterait sortirait des conditions d'utilisation d'Anthropic.
9. **Décision :** faire tourner **le vrai Claude Code**, grâce à une **couche de compatibilité Linux** dans notre noyau. (WebAssembly reste une piste annexe possible, sans décision. Revu le 24 octobre 2026 : voir la section 8.)
10. **Premier objectif concret :** que le noyau charge et exécute un petit programme Linux statique (un « bonjour » compilé normalement). Ça oblige à lire le format ELF et à implémenter les premiers appels système, `write` et `exit`. On montera ensuite petit à petit jusqu'à ce qu'il faut pour Claude Code.

## 3. Étape 1 réalisée : le secteur de démarrage

Fichiers : `01-boot/boot.asm` et `01-boot/Makefile`.

- 512 octets en assembleur NASM, chargés par le BIOS à l'adresse `0x7C00`, en mode réel 16 bits.
- Met les segments à zéro, place la pile sous le code, efface l'écran (`int 0x10`), puis affiche un message à deux endroits : à l'écran via le BIOS, et sur le port série COM1 (port `0x3F8`) avec l'instruction `out`.
- Se termine par la signature `55 AA`, sans laquelle le BIOS refuse de démarrer.
- **Vérifié dans QEMU 8.2 :** l'image fait exactement 512 octets, la signature est bien là, le message s'affiche à l'écran et sort sur le port série.

**Exercice proposé à David :** changer la valeur de `bl` dans `print` (0x0A pour du vert, 0x0C pour du rouge), puis relancer.

**À garder en tête :** c'est l'ancien démarrage BIOS. Sur un PC récent, il faut activer le mode Legacy/CSM dans le firmware, ou écrire plus tard un chargeur UEFI.

## 4. QEMU en deux mots

Un émulateur de machine : il simule un PC complet (processeur, mémoire, BIOS, disque, écran, port série). Deux modes : émulation pure, qui traduit chaque instruction et peut même émuler une autre architecture, ou virtualisation avec KVM, où le code invité tourne directement sur le vrai processeur. Idéal pour écrire un OS : un plantage ne casse rien, on redémarre en une seconde, et QEMU se branche sur GDB pour suivre le démarrage instruction par instruction (options `-s -S`).

## 5. Environnement de travail mis en place

- **Mode d'apprentissage par défaut** : dans Claude Code, le style de sortie intégré « Learning » est fixé pour le projet dans `.claude/settings.json` (`"outputStyle": "Learning"`). Dans les conversations claude.ai, le même comportement passe par les instructions du projet.
- **`CLAUDE.md`** à la racine : objectif, façon de travailler, outils, test sans écran, feuille de route.

## 6. Changement de façon de travailler (24 octobre 2026)

David préfère apprendre en lisant le code et les commentaires plutôt qu'en faisant des exercices, et ne se sent pas en mesure de trancher entre les options techniques. **Décision :** plus de `TODO(human)`. Claude écrit tout et retient, pour chaque choix, l'option qui mène au meilleur noyau à terme, en expliquant en commentaire ce qui a été écarté. Premier exemple : la GDT de l'étape 02a, en modèle « plat » comme Linux. Le style de sortie de Claude Code passe de « Learning » à « Explanatory » (explications conservées, sans demande de contribution).

## 7. Étape 2 réalisée : mode protégé, puis mode long 64 bits

**Étape 02a** (`02-mode-protege/`) : ligne A20, GDT en modèle « plat » (base 0, limite 4 Gio, comme Linux), bit PE de CR0, saut lointain, puis écriture directe en mémoire vidéo 0xB8000 et sur COM1.

**Étape 02b** (`02-mode-long/`), en quatre commits :

1. **Chargeur en deux temps.** Le passage en 64 bits ne tient plus dans les 512 octets chargés par le BIOS. Le 1er étage garde le numéro de disque (`dl`), lit les secteurs suivants en LBA (`int 0x13`, `ah=0x42`) à l'adresse 0x7E00 et y saute.
2. **Mode protégé dans le 2e étage**, puis `cpuid` (bit LM) pour vérifier que le processeur a un mode 64 bits, avec un message clair sinon.
3. **Pagination** : PML4, PDPT et PD en mémoire basse, 1 Gio en correspondance identité avec des pages de 2 Mio, puis CR4.PAE, CR3, EFER.LME et CR0.PG.
4. **Descripteur de code 64 bits** (bit L) et saut lointain : le code s'exécute en 64 bits.

**Vérifié dans QEMU** : chaque sous-étape avec `verifier.sh`, le moniteur QEMU (EFER = 0x500, CR3 = 0x1000, CS 64 bits) et le cas d'erreur d'un processeur 32 bits (`-cpu qemu32`).

## 8. Architecture hybride : WebAssembly et compatibilité Linux (24 octobre 2026)

**Point de départ :** David voulait faire de WebAssembly la voie principale.

**Vérification :** Claude Code 2.1.310 n'est livré qu'en binaire natif ELF x86_64, construit avec Bun. Il pèse environ 290 Mo, est lié dynamiquement à la glibc et est publié sous « All rights reserved ». Il n'y a pas de JavaScript séparé à récupérer. L'option « faire tourner le JavaScript de Claude Code sur un moteur JavaScript compilé en Wasm » est donc écartée : ce serait fragile (il faudrait imiter les API propres à Bun), et ce ne serait plus l'application officielle.

**Décision de David : une architecture hybride.**

- **WebAssembly devient le format natif des programmes de l'OS.** Chaque programme tourne dans le bac à sable Wasm, qui assure l'isolation (à la façon de Nebulet), avec WASI comme interface système.
- **Une couche de compatibilité Linux minimale** sert uniquement à exécuter le binaire `claude` tel quel. Comme c'est un ELF dynamique, il faudra aussi charger ld-linux et la glibc.
- **Le socle natif** reste en assembleur, puis dans le langage du noyau à choisir.

**Nouvelle feuille de route :**

3. Mémoire, interruptions, clavier.
4. Interpréteur Wasm dans le noyau : d'abord une bibliothèque testée sur l'hôte avec la suite de tests officielle, puis WASI minimal (`fd_write`, `proc_exit`).
5. Chargeur ELF et premiers appels système Linux (`write`, `exit`).
6. Processus, fichiers, réseau virtio, TLS, jusqu'à Claude Code.

## 9. Le noyau sera écrit en Rust (24 octobre 2026)

**Question :** C ou Rust pour le noyau, maintenant que le chargeur amène le processeur en 64 bits. Claude recommandait le C ; **David a choisi Rust.**

**Pourquoi Rust :**

- **Sûreté mémoire.** Le compilateur refuse les pointeurs invalides, les accès hors des tableaux et les données partagées sans protection, les erreurs qui font la majorité des failles des noyaux écrits en C.
- **`unsafe` localisé au matériel.** Les seules opérations que le compilateur ne peut pas vérifier (ports d'entrée-sortie, mémoire vidéo, registres du processeur) sont isolées dans quelques fonctions marquées `unsafe`, faciles à relire. Le reste du noyau est vérifié.
- Linux accepte lui aussi du Rust pour ses pilotes depuis 2022.

**Contreparties acceptées :**

- Moins de documentation OSDev : presque tout est écrit pour le C, il faudra transposer.
- Plus de plomberie de départ : pas de bibliothèque standard (`no_std`), une cible sans système (`x86_64-unknown-none`), un script d'édition de liens et un gestionnaire d'erreur (`panic`) à écrire soi-même.

**Règle :** aucune crate qui fait le travail à notre place. Le noyau n'utilise que `core`, et c'est notre chargeur de l'étape 02b qui le charge et lui passe la main en 64 bits.

**Révisé à l'étape 4 :** le noyau utilise aussi `alloc` (`Vec`, `Box`, `String`), servi par notre propre allocateur (buddy, puis tas par classes de taille), pour faire tourner l'interpréteur WebAssembly (section 12). `alloc` ne fournit que les structures de données ; la mémoire, c'est notre code qui la donne.

## 10. Étape 3 réalisée : un noyau Rust, ses interruptions, le clavier et la mémoire

Dossier `03-noyau-rust/` : le chargeur de l'étape 02b lit aussi le noyau sur le disque, le recopie à 1 Mio et y saute en 64 bits. Le noyau n'utilise que `core`. Un commit par morceau :

1. **Chaîne d'outils** : Rust figé par `rust-toolchain.toml`, cible `x86_64-unknown-none`, script d'édition de liens, console (écran VGA + COM1), verrou à attente active.
2. **GDT, TSS et IDT du noyau** : talons en assembleur pour les 32 exceptions, cadre de pile commun, gestionnaire Rust qui affiche l'exception (avec CR2 pour une faute de page). Pile de secours (IST) pour la double faute. Test : `int3`, puis reprise.
3. **Verrou qui coupe les interruptions** (comme `spin_lock_irqsave`), pour qu'un gestionnaire d'interruption ne bloque jamais sur un verrou tenu par le code qu'il interrompt.
4. **PIC 8259 remappé sur 32-47 et PIT à 1000 Hz** : compteur de tics, attente avec `sti; hlt`, IRQ fantômes 7 et 15 reconnues.
5. **Clavier PS/2** : 8042 reconfiguré, IRQ 1 qui range les codes dans une file, traduction du jeu 1 en AZERTY (Maj, AltGr, Verr Maj ; QWERTY en option), écho à l'écran avec les accents (page de code 437) et curseur matériel.
6. **Carte mémoire E820** lue par le chargeur en mode réel, passée au noyau dans `rdi`, recopiée et affichée.
7. **Allocateur de cadres** de 4 Kio à carte de bits, placée dans la mémoire libre après le noyau. Le premier Mio reste réservé ; au-delà du premier Gio (seul projeté par le chargeur), la mémoire est comptée mais pas encore distribuée. L'allocateur « buddy » de Linux est la cible à terme, une fois la pagination du noyau en place.

**Vérifié dans QEMU** avec `verifier.sh` (chaque commit), des touches envoyées par le moniteur QEMU (`sendkey`), une capture d'écran, et la carte mémoire avec `-m 2G` et `-m 6G`.

## 11. Relecture avant de clore une étape (24 octobre 2026)

**Constat :** l'étape 3 a été poussée et taguée, puis deux relectures ont trouvé huit défauts. Le plus sérieux : la pile du chargeur descendait dans le tampon du noyau. Les autres : une panique au milieu d'un affichage figeait la machine sans un mot ; un commentaire affirmait que l'IST protégeait du débordement de pile, ce qui était faux sans page de garde ; un débordement possible dans l'allocateur ; deux détails du clavier ; un reste d'en-tête dans le chargeur ; la GOT placée hors du script d'édition de liens. Pour que l'historique se lise toujours comme si tout avait été bien fait du premier coup, il a fallu le réécrire alors qu'il était déjà publié : push forcé, et les quatre tags recréés.

**Décision :** relecture de fond AVANT le premier push de chaque étape, en effort élevé, avec les cas d'erreur déclenchés volontairement. Les corrections sont repliées (`git commit --fixup`, puis `rebase --autosquash`) tant que rien n'est publié. La marche à suivre, et le cas exceptionnel d'un historique déjà poussé, sont dans le skill `.claude/skills/fin-d-etape/`, avec un script qui vérifie chaque commit.

## 12. Étape 4 réalisée : un interpréteur WebAssembly, dans le noyau

Dossier `04-wasm/`, en quatre sous-étapes.

**1. Décodeur et banc d'essai** (`wasm/`, une bibliothèque `no_std` + `alloc`). Lit un module `.wasm` 2.0 sans SIMD ; le code n'est pas traduit, on garde la plage de chaque corps de fonction. Le banc rejoue la suite officielle de la spécification (tag wg-2.0), convertie par `wast2json`. **Décision de David :** wabt 1.0.39, téléchargé comme la suite par le Makefile, à une version figée vérifiée par SHA-256 (wabt 1.0.34 d'Ubuntu ne lisait pas deux fichiers de la suite) ; le paquet `apt` n'est plus nécessaire. Limites d'implémentation (`limites.rs`), celles des navigateurs : module de 1 Gio, corps de fonction de 7,6 Mo, 1000 paramètres et 1000 résultats, 50 000 locales.

**2. Validateur.** L'algorithme de l'annexe de la spécification (pile de types, pile de cadres, une seule passe, pile polymorphe dans le code inaccessible). `valider` rend un `ModuleValide` aux champs privés : impossible d'exécuter un module non validé. Il ne suppose rien du `Module` reçu. Il calcule aussi la **table annexe des branchements** : l'interpréteur lit les octets du code tels quels (« interprétation sur place », Titzer 2022, moteur Wizard), la table lui dit où mène chaque branchement.

**3. Interpréteur.** Cases de pile de 64 bits non typées, pile d'appels explicite sur le tas (non récursif : une récursion WebAssembly ne touche jamais la pile du noyau), **carburant** (une exécution s'interrompt après N unités et se reprend au même point ; une instruction qui touche beaucoup d'octets, ou l'hôte, ajoute une dette). Flottants exacts en arithmétique entière, NaN canoniques : résultats identiques sur l'hôte et dans le noyau. Un magasin avec un budget mémoire ; une instanciation qui échoue ne laisse rien ; la fonction de démarrage est rendue comme une `Execution`, à faire tourner au carburant. Suite officielle : **27 437 commandes réussies, 0 échec** (581 modules au format texte ignorés).

**4. Dans le noyau.**
- Noyau dans la moitié haute (`0xffffffff80100000`, chargé à 1 Mio par `AT()`) ; `_start` construit ses tables de démarrage comme `head_64.S` de Linux, le chargeur n'a rien de plus à fournir (un chargeur UEFI non plus).
- Tables définitives : pages de 4 Kio W^X pour le noyau (EFER.NXE, CR0.WP), projection directe de la mémoire vive seule (`0xffff888000000000`), alias du code en lecture seule, plus d'identité. Sans NX (ou NX caché par le BIOS d'un Intel, qu'on démasque comme Linux), le noyau s'en passe et le dit.
- Pages de garde sous la pile du noyau et sous la pile de secours de la double faute.
- La carte de bits de l'étape 3 devient l'allocateur de démarrage (`memblock`) et cède la mémoire à un **allocateur buddy** ; un **tas** par classes de 16 à 2048 octets (SLUB simplifié) sert `alloc`.
- **WASI minimal** (`fd_write`, `proc_exit`) ; un programme écrit en Rust et compilé par `rustc` (`bonjour/`, 2943 octets) affiche un bonjour et dix nombres premiers, exécuté par tranches de carburant. Le noyau pèse 157 Kio.

**Outillage :** `verifier.sh` lance aussi `make tests-hote` (les tests sur la machine hôte) et `make tests-qemu` (des scénarios de panne : un noyau qui déborde exprès de sa pile doit le dire). `make test` garde partout le sens « démarrer dans QEMU ». Les tuyaux des Makefile passent par `pipefail` (un test en échec passait inaperçu).

**Relectures :** trois relecteurs indépendants (des agents lancés sans nos conclusions, un par sous-ensemble), du fuzzing (dizaines de millions de modules corrompus, exécutés d'une traite puis par tranches), des mutations volontaires pour vérifier que les tests mordent, et les fautes provoquées dans QEMU (écriture dans le code, exécution des données, débordement de pile, 128 Mio à 6 Gio, processeur sans NX). Chaque défaut trouvé a été replié dans le commit qui l'avait introduit.

## 13. Étape 5 réalisée : un programme Linux dans l'anneau 3

Dossier `05-elf/`, en onze commits (outillage compris), d'après un plan relu à l'avance contre le code et contre un vrai `gcc -static` tracé par `strace`. Un programme C ordinaire (`linux/bonjour.c` : `printf`, `malloc`, `getauxval`), compilé par `gcc -static` avec la glibc d'Ubuntu, tourne dans le noyau à côté du bonjour WebAssembly.

1. **Chargeur en mode irréel.** Le noyau et ses programmes ne tiennent plus dans les 576 Kio de mémoire basse : le chargeur lit 32 Kio à la fois dans un petit tampon, puis recopie chaque morceau au-dessus de 1 Mio (`a32 rep movsd`, DS et ES gardant une limite de 4 Gio après un passage éclair en mode protégé, refait avant chaque copie, interruptions coupées jusqu'à la fin de la copie). Destination vérifiée dans la carte E820 (lue par un tampon fixe, jetée si le BIOS cesse de répondre « SMAP », comme Linux) ; trois essais par lecture ; comptes de secteurs sur 32 bits, pour les 600 000 secteurs de `claude`.
2. **Archive de programmes**, au format de l'initramfs de Linux (cpio newc), fabriquée par `archive.sh` et déposée après la place du noyau en mémoire (mesurée comme `init_size`). Le chargeur passe au noyau une structure d'informations de démarrage (les `boot_params` de Linux, versionnée par sa taille). Le noyau exécute chaque fichier, reconnu à sa signature (les binfmt de Linux).
3. **Un espace d'adressage par programme** : sa moitié basse, la moitié haute du noyau en copie ; bit U à tous les niveaux en bas, jamais en haut ; tables prises au buddy ; adresses de 64 Kio à `0x7fff_ffff_f000` (`mmap_min_addr`, `TASK_SIZE_MAX`) ; toute allocation pour un programme faillible.
4. **Chargeur ELF** : validation complète par une bibliothèque `no_std` sans `unsafe` (`formats/`, avec la lecture cpio), testée sur l'hôte contre de vrais binaires (gcc statique, PIE, dynamique, `ld -N`) et des variantes abîmées. ET_EXEC seulement, jamais W+X.
5. **Anneau 3 et `syscall`** (choix de conception) : GDT dans l'ordre de STAR, entrée qui range le RSP du programme dans `TSS.rsp2` et construit le même cadre que les interruptions, retour par `sysretq` seulement si RIP est dans la moitié basse (CVE-2012-0217), sinon `iretq`. Pas de `swapgs` avant le multiprocesseur. NMI, #DB, #MC et double faute sur leur pile IST. Le programme est une tâche : sa pile noyau, un contexte, `basculer` (`__switch_to_asm`).
6. **Un programme fautif est arrêté, le noyau continue** : décision d'après `CS & 3` pour tous les vecteurs, signal de Linux et code de sortie 128 + N ; budget de temps de 1 s (SIGXCPU). `make tests-qemu` démarre une archive de programmes fautifs (une vingtaine, nasm + ld, qui font la même faute sous Linux sur l'hôte) avec qemu64 puis `-cpu max`, et le noyau éteint QEMU à la fin.
7. **Copies vers et depuis les programmes** : bornes d'abord, puis `stac ; rep movsb ; clac` protégé par une table d'exceptions (`__ex_table`) ; SMEP, SMAP, UMIP quand le processeur les a ; `clac` en tête de chaque talon d'interruption.
8. **Pile initiale** : argv, envp, vecteur auxiliaire (AT_PHDR, AT_RANDOM...), RSP aligné sur 16. Identité : l'utilisateur 1000, pas root. Aléa : RDRAND, sinon le compteur de cycles brassé (non cryptographique, et le noyau le dit).
9. **SSE pour les programmes, sans XSAVE** (choix de conception) : FXSR seulement, pas d'AVX promis ; chaque programme part d'un état x87/SSE propre (`fxrstor` d'une image initiale).
10. **Appels système de la glibc statique** : brk (vrai tas, budget de mémoire), arch_prctl, mprotect réel (W+X permis, PROT_NONE), fstat, getrandom, prlimit64... `make trace` affiche la même suite d'appels que `strace` sur l'hôte.

**Relecture de fond :** quatre relecteurs indépendants, 60 millions d'ELF et 40 millions d'archives abîmés (aucune panique, invariants vérifiés), des mutations, des cas provoqués (`-cpu qemu32`, 128 Mio à 6 Gio, sans NX, image tronquée, erreurs disque injectées par `blkdebug`, NMI injecté pendant un programme). Deux vrais défauts, repliés dans leurs commits : les registres x87/MMX passaient d'un programme au suivant (`fninit` ne les efface pas), et un programme échappait à son budget de temps par `brk` (pages mises à zéro interruptions coupées, tics perdus). Plus une série de points de robustesse (chargeur sur vrai matériel, Makefile, petits écarts avec Linux).

## 14. Reste à faire

**Dans le noyau**

- **Allocations faillibles.** Une allocation impossible, hors de `try_reserve`, fait paniquer le noyau. Rust pour Linux n'utilise que des allocations qui rendent une erreur : à généraliser avant que des programmes puissent en abuser.
- **Grandes allocations.** Un bloc du tas ne dépasse pas 4 Mio (l'ordre maximal du buddy) : il faudra projeter des pages éparses d'un seul tenant (`vmalloc`). Pour les mémoires WebAssembly, réserver 4 Gio d'adresses suivies de pages de garde (comme wasmtime), ce qui supprimera aussi le contrôle des bornes une fois le code compilé.
- **Validation sous carburant.** Valider un module piégé coûte jusqu'à environ 1 s par Mio (le facteur 1000 de l'algorithme de la spécification) ; l'instanciation copie les segments actifs sans carburant (linéaire en la taille du module). À rendre interruptible avec l'ordonnanceur.
- **Console non bloquante.** Le port série fait attendre activement (87 µs par octet sur du vrai matériel) : un pilote à interruptions et une file d'attente, comme le tty de Linux.
- **Registres des périphériques** (ACPI, APIC…) : les projeter à la demande, sans cache (`ioremap`) ; la projection directe ne couvre que la mémoire vive.
- **Pages globales** (CR4.PGE) pour le noyau, maintenant qu'il y a un espace d'adressage par programme ; KPTI et PCID quand on saura sur quels processeurs on tourne.
- **Copie de la moitié haute des espaces d'adressage** : elle suppose que la PML4 du noyau ne change plus. Avec `vmalloc`, créer d'avance toutes les tables de second niveau de la moitié haute (`preallocate_vmalloc_pages` de Linux).
- **`iretq` qui fauterait** (un RIP non canonique écrit par le noyau, pour exec ou les signaux) : une entrée de la table d'exceptions qui transforme la faute en signal pour le programme (`bad_iret` de Linux). Inatteignable aujourd'hui : le RIP d'un cadre vient toujours du programme.
- **Budget de temps au compteur de cycles** : compté en tics d'horloge, il se laisse un peu tromper sous QEMU sans accélération (tics perdus dans de courtes sections critiques). Avec une horloge fine (TSC, HPET), mesurer le temps réel.
- **Tables de pages hors budget** de mémoire d'un programme : les compter, comme Linux (`pgtables_bytes`), avant mmap.
- **Lecture des formats** : `formats/` relit les octets après les avoir validés. Sans risque tant qu'ils viennent de l'archive en lecture seule ; valider une copie le jour où ils viendront d'une mémoire modifiable (le cache des fichiers, execve).
- **Archive cpio** : liens physiques (nlink > 1, contenu dans la dernière entrée), archives concaténées et compressées.
- **PT_GNU_STACK exécutable** : ignoré, la pile reste NX ; un programme qui l'exige (fonctions imbriquées de gcc) plante au lieu d'être refusé avec un message.
- **writev** : vérifier tous les morceaux avant d'écrire, comme Linux.
- **Tas :** rendre au buddy les pages vides des classes ; des listes par processeur pour le multiprocesseur.

**Pour le vrai matériel**

- **NMI pendant le passage éclair en mode protégé du chargeur** : non masqué (Linux le masque par le port 0x70 pour son passage définitif). Risque infime, à revoir si un essai sur vrai matériel le montre.
- **Démarrage sur clé USB : réserver un BPB factice dans le secteur 0.** Pour une clé, certains BIOS « émulent » une disquette et croient trouver au début du secteur 0 un BPB (BIOS Parameter Block, la description d'un système de fichiers FAT) : ils réécrivent les octets 3 à 0x5A avec leurs propres valeurs, ce qui écraserait notre code. Avant le premier essai sur clé, le secteur 0 devra commencer par un saut court par-dessus une zone de 0x5A octets laissée libre.

## 15. Questions ouvertes

- Aucune pour l'instant.

## 16. Prochaine étape

Étape 6 : vers Claude Code. Le plan de l'étape 5 en a reporté la liste : ET_DYN, ld-linux et la glibc partagée (`claude` est dynamique) ; mmap et la pagination à la demande ; l'ordonnanceur, les fils d'exécution, la sauvegarde XSAVE à chaque bascule ; un vrai tty ; un vrai générateur aléatoire ; un système de fichiers en mémoire rempli depuis l'archive, et /proc/self/exe ; KPTI, PCID, pages globales ; ASLR ; vDSO. Puis le réseau (virtio) et TLS.
