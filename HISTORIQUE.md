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

**Révisé en 6h (relecture globale, section 21) :** « `unsafe` localisé au matériel » ne décrivait plus la réalité. Un noyau a aussi besoin d'`unsafe` pour la mémoire physique, les copies vers les programmes, la synchronisation et la bascule de contexte (Rust pour Linux a les mêmes familles dans sa crate `kernel`). La règle devient : `unsafe` seulement dans ces modules d'abstraction, nommés dans `main.rs` et vérifiés par le compilateur, chaque bloc justifié ; jamais dans les bibliothèques ni dans la logique des appels système. Et les allocations du noyau ne paniquent plus (`faillible.rs`).

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

## 14. Sous-étape 6a réalisée : la mémoire virtuelle à la demande

L'étape 6 se découpe en treize sous-étapes (voir `CLAUDE.md`), chacune dans son dossier, avec son plan écrit et relu au début de son fil, d'après le vrai binaire `claude` 2.1.310 (lu par `readelf`, tracé par `strace`, essayé sous `qemu-x86_64` : Nehalem suffit, pas besoin d'AVX ni de XSAVE ; TLS est fait par Bun, pas par le noyau). `claude` réserve 8 Gio pour n'en toucher que quelques Mio : rien ne peut plus être projeté d'avance.

Dossier `06a-memoire/`, en dix commits (outillage compris) :

0. **Outillage** : `verifier.sh` et `verifier-historique.sh` voient les dossiers de sous-étapes (`[0-9][0-9]*-*/`), le `.gitignore` passe à des motifs.
1. **La carte des zones** (`zones/`, les `vm_area_struct` de Linux), bibliothèque `no_std` sans `unsafe` : un `Vec` trié plutôt qu'un arbre (78 zones mesurées pour `claude`, et un `Vec` sait échouer proprement), voisines du même genre toujours fusionnées, au plus 65 530 zones, toute opération tout ou rien. Testée par des cas à la main et 400 000 opérations au hasard comparées à un modèle page par page, qui a trouvé un vrai défaut (une plage vide au milieu d'une zone la coupait).
2. **Chaque programme a sa mémoire** (`memoire.rs`, la `mm_struct`) : segments, pile et tas deviennent des zones ; les tables se parcourent par plages en sautant les tables absentes (un munmap de 64 Gio ne coûte que ce qui est projeté) ; un lot vide le TLB avant de rendre les cadres (33 invlpg au plus, sinon CR3). Comportement inchangé.
3. **Fautes de page servies** (choix de conception) : dans l'ordre de `do_user_addr_fault` ; la page de zéros dans `.rodata`, la copie à l'écriture ; la pile qui grandit jusqu'à 8 Mio avec l'écart de garde de 1 Mio ; le .bss (zone anonyme à part, comme Linux) et le tas paresseux ; les copies du noyau servies puis reprises, seulement avec AC à 1 si SMAP est actif ; les messages disent la zone de RIP (« dans recursion[401000+1000] ») ; un verrou déjà pris panique au lieu de boucler.
4. **La politique de Linux** (choix de conception) remplace le budget fixe : surengagement (`OVERCOMMIT_GUESS`), réserve du noyau (`min_free_kbytes`), tueur OOM (SIGKILL), tables comptées, `sysinfo`.
5. **mmap et munmap anonymes** : placement de Linux (adresse suggérée arrondie à la page inférieure, puis du haut vers le bas sous la base des projections), MAP_FIXED tout ou rien, tables vides rendues après le vidage du TLB.
6. **mprotect et madvise** sur les zones, dans l'ordre et avec les codes d'erreur de Linux ; MADV_DONTNEED sans effet sur les pages du fichier (Bun y rend 54 Mo de sa section `.bun`) jusqu'au cache des fichiers.
7. **Pile exécutable** si le programme la demande (PT_GNU_STACK avec PF_X).
8. **La mémoire de `claude --version` rejouée** par un programme C, dans le même ordre et avec les mêmes tailles : « Memoire de claude --version rejouee : ok. » sur 128 Mio.

`linux/memoire.c` vérifie une quarantaine de comportements ligne par ligne, dans notre noyau et sur l'hôte (`make tests-hote`) : nos codes d'erreur sont ceux du vrai Linux, sans dépendre des réglages de l'hôte.

**Ce que le plan avait de faux, corrigé en route :** une seule demande de 300 Mio sur une machine de 128 Mio, que le plan voulait accepter, serait refusée par Linux lui-même (une demande plus grande que toute la mémoire) ; le test promet donc 2 × 100 Mio. L'adresse suggérée à mmap est arrondie à la page inférieure, pas supérieure (mesuré). `MADV_HUGEPAGE` est accepté comme sur un Linux dont les grandes pages sont réglées sur « never ».

**Relecture de fond :** un relecteur indépendant (aucun défaut grave ; deux écarts avec Linux corrigés : MADV_FREE refusé sur les pages du fichier, le .bss en zone anonyme ; la pile initiale quand arguments et environnement frôlent leurs 2 Mio ; deux commentaires), des cas provoqués (64 Mio à 5 Gio, interblocage, copie du noyau sans mémoire, écart de garde de la pile) et 24 000 opérations mémoire au hasard, identiques sous Linux et chez nous, avec qemu64 et `-cpu max`.

## 15. Sous-étape 6b réalisée : les fichiers

Dossier `06b-fichiers/`, en treize commits (et un d'outillage), d'après le plan écrit et relu au début de son fil (`plan-6b.md` dans les fichiers du projet) :

1. **La bibliothèque des fichiers** (`fichiers/`, `no_std` sans `unsafe`, testée sur l'hôte) : le tmpfs de Linux (inodes dans une table à deux niveaux, dossiers lus du plus récent au plus ancien avec des positions stables, l'ordre de Linux 6.18), l'index des pages d'un fichier (un arbre à 512 branches, comme les tables de pages : un fichier creux ne coûte que ses pages écrites), la résolution des chemins (le `namei` de Linux, sans récursion, avec la résolution « sous » un dossier pour WASI). Chaque opération fait les vérifications de Linux dans son ordre, tout ou rien. Des milliers d'opérations au hasard comparées à un modèle naïf.
2. **Un descripteur par cadre** (choix de conception) : 8 octets par cadre, la `struct page` de Linux réduite à l'état du buddy, un compteur de références, des drapeaux et les objets occupés d'une page du tas.
3. **Le tas rend ses pages vides** (le `inuse` du slab), un point de « Reste à faire » devenu nécessaire : sans lui, le premier programme qui crée des fichiers aurait fait mentir « mémoire rendue ».
4. **L'heure, de l'horloge CMOS**, lue une fois au démarrage, puis avancée avec les tics à leur durée exacte ; les horloges de `clock_gettime`.
5. **Les exécutables lus par leurs en-têtes** : `formats::elf` vérifie une copie de l'en-tête et de la table, plus jamais le fichier entier (un point de « Reste à faire »).
6. **Le système de fichiers en mémoire**, monté à la racine et déballé de l'archive cpio (liens physiques compris), `/dev` comme le devtmpfs ; les programmes sont les fichiers de `/bin`.
7. **Les descripteurs de fichiers** : le fichier ouvert et la table de chaque processus, comme Linux ; une cinquantaine d'appels (open, read, write, lseek, stat, dup, fcntl, ioctl...) ; la console devient `/dev/console`.
8. **L'arborescence par les appels système** : mkdir, liens, rename, getdents64, getcwd, chdir, truncate, chmod, chown, utimensat...
9. **Les zones apprennent les fichiers** : une zone tient le fichier qu'elle projette, et les fusions suivent les pages du fichier.
10. **mmap de fichiers, en privé** (choix de conception) : la page du fichier elle-même en lecture seule, copiée à la première écriture ; SIGBUS au-delà de la fin ; MADV_DONTNEED fait relire le fichier.
11. **Le chargeur ELF projette le fichier** : il ne copie plus rien, les segments viennent à la faute ; le .bss aux règles de Linux.
12. **WASI, les fichiers** : `path_open`, `fd_read`, `fd_readdir`..., chaque chemin enfermé sous le dossier pré-ouvert (EPERM, comme wasmtime). Le format natif de l'OS voit le même arbre que les programmes Linux.

`linux/fichiers.c` vérifie près de deux cents comportements, dans notre noyau et sur l'hôte (`make tests-hote`), sans rien supposer du système de fichiers de l'hôte.

**Une panne en route :** un test parti en boucle infinie a rempli toute la mémoire de WSL, qui s'est figé avec Docker et VS Code. Le conteneur est maintenant plafonné à 8 Go (commit d'outillage), et les tests qui peuvent s'emballer se lancent avec `ulimit -v` et `timeout`.

**Relecture de fond :** trois relecteurs indépendants (la bibliothèque, les appels système, la mémoire avec ELF et WASI), chaque constat mesuré par une sonde C sur l'hôte et dans notre noyau. Le cœur mémoire tenait (aucun cadre rendu encore projeté, aucune fuite des octets d'après la fin d'un fichier) ; 29 constats corrigés, chacun avec un test, repliés dans leurs commits :
- read et write qui font une faute au milieu du tampon rendent ce qu'ils ont transféré (les octets étaient écrits, l'appel disait EFAULT) ; la plage entière du tampon est vérifiée d'abord (access_ok), et la position plus la longueur reste sous 2^63 ;
- un exécutable setgid créé dans le dossier setgid d'un groupe étranger perd son bit (la faille CVE-2018-13405) ; chown et utimensat suivent les règles de Linux pour les bits spéciaux et les dates ;
- l'horloge CMOS est attendue 10 ms au plus (sans horloge, le démarrage se figeait) ;
- la carte des zones ne double plus au-delà de son maximum (3 Mio au lieu de 4) ;
- une vingtaine d'écarts de codes d'erreur ou d'ordre des vérifications (open, utimensat, fcntl et ses verrous, FIONREAD, lseek, readv, prlimit64...), et des commentaires devenus faux.

## 16. Sous-étape 6c réalisée : les programmes dynamiques

Dossier `06c-dynamique/`, en cinq commits, d'après le plan écrit au début de son fil et relu deux fois par des relecteurs indépendants, la seconde en effort élevé (`plan-6c.md` dans les fichiers du projet ; 18 puis 11 constats intégrés avant de coder). **Décision de David :** copier la glibc de la machine dans l'archive de démarrage (rien n'est téléchargé ni commité), et le lanceur `/etc/demarrage`.

1. **Les exécutables ET_DYN et PT_INTERP, lus par `formats::elf`** : la disposition relative des segments d'abord, puis `Executable::placer` pose l'image à l'adresse choisie par le noyau (le `load_bias` de Linux) ; seule l'image placée donne des adresses absolues. PT_INTERP (le premier, de 2 à 4096 octets, le préfixe jusqu'au premier zéro, comme Linux), l'alignement (`maximum_alignment`), l'étendue (`total_mapping_size`). Testé sur de vrais fichiers par des propriétés, et par 20 000 mutations à graine fixe contrôlées par un second calcul indépendant.
2. **Le lanceur, `/etc/demarrage`** (choix de conception) : sans `fork` ni `execve` (6l), le noyau joue le rôle d'`init` et lance une commande par ligne, avec ses arguments et son environnement. Un sous-ensemble strict de la syntaxe du `sh` de POSIX (dash), vérifié contre le `sh` de la machine : le programme par son chemin absolu, `NOM=valeur` en tête, et une seule entorse, `--dir=` pour les dossiers pré-ouverts d'un programme WebAssembly. Le droit d'exécuter vérifié avant tout, pour tous les formats ; plus de limite de 32 arguments (celles de Linux : la place, 128 Kio par chaîne) ; WASI apprend une table des dossiers pré-ouverts, `args_get` et `environ_get`.
3. **Les ET_DYN placés par le noyau** : un `gcc -static-pie` posé comme une projection, du haut vers le bas, à son alignement (`Zones::trou` apprend l'alignement) ; son tas à `ELF_ET_DYN_BASE` (0x555555555000), comme Linux 6.18, pour ne pas buter contre la pile.
4. **PT_INTERP : le noyau charge ld-linux** (choix de conception : le noyau ne charge que le programme et son interpréteur ; ld-linux projette lui-même la glibc). Un PIE à 0x555555554000, ld-linux tout en haut des projections, AT_BASE, AT_ENTRY, le départ à l'entrée de l'interpréteur ; l'interpréteur protégé contre l'écriture le temps du chargement seulement, ses erreurs avec l'errno de Linux (ENOENT, EACCES, EIO, ELIBBAD, ENOEXEC). La glibc de la machine copiée dans `glibc/` aux chemins d'Ubuntu (`/usr` fusionné), avec un `/etc/ld.so.cache` fabriqué par `ldconfig -r`. `bonjour-c-dynamique` tourne, lancé par le noyau comme par ld-linux à la main ; `make trace` montre les mêmes appels que `strace` sur l'hôte (sauf `rseq`, ENOSYS, et une allocation de ld-linux qui dépend des glibc-hwcaps du processeur).
5. **Les bibliothèques de `claude`, et `dlopen`** : `libm`, `libpthread`, `libdl`, `librt` ; `linux/dynamique.c`, lié aux cinq (`-l:libpthread.so.0`... : depuis la glibc 2.34, `-lpthread` ne lie plus rien), charge une bibliothèque à nous de `/usr/local/lib` (constructeur, destructeur, variable `__thread` : le TLS dynamique), sur l'hôte comme chez nous. Aucun appel système nouveau : 6b avait tout ce que demandent ld-linux, `dlopen` et le TLS.

**Relecture de fond :** trois relecteurs indépendants en effort élevé (les bibliothèques, le noyau, la construction et l'historique). Bibliothèques sans défaut grave sur 80 millions d'ELF comparés à un modèle en u128, 12 millions de mutations de vrais fichiers, 300 000 lignes comparées à dash ; aucune fuite de référence sur 45 lignes piégées. 25 constats, repliés dans leurs commits, chacun avec un test :
- **une panique du noyau** : une ligne de `/etc/demarrage` qui désigne un dossier (la signature était lue avant de vérifier le droit d'exécuter) ;
- une barre finale ignorée (`/bin/x/` exécutait le fichier, Linux dit ENOTDIR), une fuite de la console quand WASI manque de place, « memoire rendue : ECHEC » à tort pour un interpréteur à grosse table, un static-pie refusé quand sa première adresse tombait dans la région de la pile ;
- des tests qui ne mordaient pas : `interp-milieu` écrivait sa ligne sans ld-linux, la fin de `dlclose` était vérifiée par ld-linux et non par le noyau, des lignes refusées attendues sans leur numéro, un `argv` vérifié par un préfixe, quatre mutations survivantes ;
- la copie de la glibc décidée par la date (dpkg garde celle de la construction du paquet) : par le contenu désormais ; la vérification de version trop stricte pour la CI (la révision d'Ubuntu, au lieu de 2.39) ;
- la promesse « sous-ensemble strict de sh », fausse pour un mot réservé en tête (`if /bin/x`) : le chemin absolu exigé par la bibliothèque ;
- des écarts avec Linux écrits en commentaire, des commentaires faux, `DUREE` portée à 12 s (14,6 s mesurées sur une machine saturée par les trois relectures, dont les délais fixes faisaient échouer `verifier-historique.sh` à tort).

## 17. Sous-étape 6d réalisée : `claude --version`

Dossier `06d-claude-version/`, en onze commits (et un d'outillage), d'après le plan écrit au début de son fil et relu par un relecteur indépendant (`plan-6d.md` et `relecture-6d.md` dans les fichiers du projet ; 16 constats intégrés avant de coder). **Décision de David :** son accord écrit pour télécharger et exécuter le vrai `claude` 2.1.310, ici et dans la CI. **Le jalon :** notre OS affiche « 2.1.310 (Claude Code) » sur le port série, `claude` sort avec 0 et rend toute sa mémoire ; du premier coup, sans un seul appel système inconnu.

1. **RLIMIT_CPU remplace le budget de temps** : le temps de calcul compté tic par tic, comme Linux, infini par défaut ; la limite dure (SIGKILL), puis la courante (SIGXCPU, relevée d'une seconde), vérifiées après chaque tic compté.
2. **Les signaux enregistrés** : `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `sigaltstack`, `kill`, `tkill`, `tgkill`, rendus comme Linux ; SIG_IGN, l'action par défaut et l'attente appliquées au retour vers l'anneau 3, ceux du fil avant ceux du processus. Un gestionnaire n'est pas encore appelé (6f). Un numéro par programme, à partir de 2.
3. **futex, uname, sched_getaffinity, prctl**, exacts pour un seul fil.
4. **Les points de montage** (choix de conception) : /proc et /sys sont de vrais systèmes de fichiers, montés sur des dossiers du tmpfs, comme le `vfsmount` de Linux ; un objet est un couple (système, inode), la résolution parcourt une vue de tous les systèmes (chemins.rs n'a pas changé d'une ligne).
5. **eventfd et epoll** : la boucle d'événements de Bun, créée mais pas encore attendue (`epoll_wait` en 6f) ; l'inode anonyme.
6. **Le chemin canonique des fichiers ouverts**, celui que montre maps.
7. **/proc** : `fichiers::noyaufs`, un système de fichiers dont le noyau décrit l'arborescence et fabrique le contenu à la lecture (`seq_file`) ; `/proc/self`, `/proc/<pid>/maps`, `statm`, `exe`, `/proc/sys/vm`.
8. **/sys** : le nombre de processeurs et le réglage des grandes pages, en attributs de kernfs.
9. **La machine de l'étape** : un disque virtio (le BIOS de QEMU lit les 307 Mo de l'archive en 3,8 s, contre 74 s en IDE, avec le même chargeur), un processeur Nehalem, 2 Gio, que `verifier.sh` demande à l'étape ; les images ne recopient plus leur archive ; `make tests-qemu` arrête QEMU dès la ligne cherchée (30 s au lieu de 88).
10. **Le binaire de claude, téléchargé et vérifié** (choix de conception) : le paquet npm officiel de la plateforme, à une version figée, l'empreinte SHA-256 du binaire vérifiée, gardé dans `~/.cache/claude-os`, jamais commité ni publié.
11. **`claude --version`**, en dernier dans `/etc/demarrage` ; `make trace` montre ses appels dans notre noyau, et leurs seuls noms sous Linux (sans environnement ni HOME : jamais une trace qui pourrait contenir un jeton).

**Relecture de fond :** trois relecteurs indépendants (le noyau, les bibliothèques, la construction et l'historique), chaque constat mesuré par une sonde C sur l'hôte (Linux 6.18) et dans notre noyau ; leurs notes, perdues avec la reconstruction du conteneur, ont été retrouvées dans les journaux de la session. Aucun défaut grave : ni réentrance de verrou, ni verrou tenu pendant un arrêt, ni fuite de mémoire. 41 constats, repliés dans leurs commits, chacun avec un test qui échouait avant :
- **un défaut latent pour 6l** : un fichier de /proc gardé ouvert après la fin de son processus aurait fait paniquer le noyau, ou désigné en silence le fichier d'un autre processus (les numéros d'inode étaient repris) ; ils ne le sont plus, et un objet disparu répond ENOENT ;
- **deux tests qui ne prouvaient rien** : rien ne vérifiait QUAND RLIMIT_CPU tombe (une limite comptée deux fois trop tard passait), et une ligne de `signaux.c` disait « ok » quoi qu'il arrive ; et un test de `statm` qui aurait échoué sur le noyau 6.8 de la CI (ses compteurs approchés) ;
- une trentaine d'écarts avec Linux, mesurés : `O_NOFOLLOW`, `O_TRUNC`, `O_CREAT` dans /proc, la barre finale et les drapeaux de `renameat2` dans un système monté, `fsync` (EINVAL pour ce qui n'en a pas), `readv` d'un eventfd, la profondeur d'epoll, FUTEX_WAKE_OP, l'ordre des signaux, `sigaltstack`, `lseek` des décalages négatifs, FIONREAD, les attributs de l'inode anonyme (EOPNOTSUPP) et du dossier d'un processus (immuable), la taille des liens et les liens des dossiers de /proc/sys, et les lectures de /proc, désormais par pages de lignes entières comme le `seq_file` de Linux ;
- la construction : le binaire du cache revérifié à chaque archive, un téléchargement qui ne laisse rien derrière lui, `make capture` qui photographiait le chargeur, `make trace` muet quand strace manque ;
- un défaut hérité de l'étape 3, apparu quand le noyau a grandi : l'allocateur de cadres ne reprenait un cadre rendu qu'après un tour de la mémoire (il le reprend d'abord, encore chaud dans le cache).

Et le dernier commit de l'étape, trop gros, coupé en trois : la machine, le binaire, le jalon.

## 18. Sous-étape 6e réalisée : l'ordonnanceur, l'APIC et les fils

Dossier `06e-ordonnanceur/`, en dix-huit commits, d'après le plan écrit au début de son fil et relu par un relecteur indépendant (`plan-6e.md` et `relecture-plan.md` dans les fichiers du projet ; 26 constats intégrés avant de coder, dont 3 graves). **Le jalon :** des programmes à plusieurs fils, écrits avec la glibc (pthread), tournent dans notre noyau comme sous Linux, et `claude --version` passe toujours, en dernier.

1. **vmalloc et ioremap** : des adresses du noyau à la demande, les piles des tâches sous une page de garde, les registres des périphériques projetés sans cache.
2. **Reste de 6d** : les ioctl de /dev/urandom sont ceux de son pilote.
3. **Les tables ACPI** (RSDP, RSDT ou XSDT, MADT, FADT), lues par `formats/` et testées sur l'hôte avec les tables capturées de QEMU ; le siècle de l'horloge CMOS.
4. **L'APIC local et l'IO-APIC** remplacent le 8259 (gardé en repli, sans ACPI ou sans IO-APIC).
5. **Le TSC étalonné** contre le PIT, et le timer de l'APIC à 1000 Hz ; le temps à la nanoseconde.
6. **On ne meurt qu'au retour vers l'anneau 3** (choix de conception) : une faute, exit, le tueur OOM ne font que prévoir la fin.
7. **Une pile noyau par tâche**, et la bascule (`__switch_to`), interruptions coupées ; la pile d'une morte rendue par la suivante.
8. **L'ordonnanceur EEVDF** de Linux 6.6 (choix de conception), et la préemption du noyau ; un compteur de verrous fait paniquer qui céderait le processeur verrou tenu.
9. **Dormir et se réveiller** : files d'attente chaînées par les tâches, minuteries, nanosleep et clock_nanosleep, un verrou qui dort.
10. **futex et eventfd attendent vraiment** ; un détecteur d'interblocage.
11. **Deux programmes à la fois** : `&` et `wait` dans `/etc/demarrage`, kill et tgkill entre processus.
12. **Reste de 6d** : un fichier de /proc d'un processus recueilli rend ESRCH.
13. **XSAVE** : l'état AVX de chaque tâche.
14. **Des descripteurs tenus le temps d'un appel** (choix de conception) : le `fdget` de Linux, les numéros réservés, les dossiers et les objets tenus pendant une résolution, la position d'un fichier sous son verrou ; sans cela, un `close` d'un autre fil arrête le noyau.
15. **Le processus et ses fils** (choix de conception) : ce qui est au processus (la mémoire, les descripteurs, l'action des signaux, la fin du groupe) et ce qui est à chaque fil (son numéro, son masque, ses signaux, sa pile de secours) ; le processus devient zombie avec son dernier fil.
16. **clone et clone3**, dans l'ordre de `kernel/fork.c` ; la fin d'un fil (liste robuste, CLONE_CHILD_CLEARTID), la fin du groupe.
17. **/proc et les fils** : `comm`, `task/<tid>/comm`, `/proc/thread-self`.
18. **Des programmes à plusieurs fils** : `fils.c` (verrous, conditions, __thread, un verrou robuste, deux cents fils) et `courses.c` (quatre fils qui ferment, changent de dossier et se servent en même temps des mêmes descripteurs ; il fait paniquer un noyau sans le commit 14).

**Pendant l'étape :** la signature des commits par 1Password a cessé de marcher dans le conteneur un soir ; les commits 9 à 15 ont attendu en patchs, que David a créés et signés depuis WSL, et la signature est revenue d'elle-même.

**Relecture de fond :** trois relecteurs indépendants (le cœur du noyau ; les fichiers, les processus et les fils ; la construction, les tests et l'historique), chaque constat vérifié par une sonde ou une mutation. Aucune faille ni corruption de la mémoire. Repliés dans leurs commits :
- **un programme pouvait geler la machine** : FUTEX_REQUEUE d'une adresse vers elle-même tournait `val2` fois interruptions coupées (des minutes pour 2^31) ;
- **la cause d'un « memoire rendue : ECHEC » rare** : le processus devenait zombie pendant qu'un de ses fils, préempté, n'avait pas fini de mourir ; il ne l'est plus qu'à la fin de bascule qui rend la pile du dernier ;
- **le repli sur le 8259 figeait le démarrage** sans IO-APIC (LINT0 masquée) : le « fil virtuel » de Linux ;
- la troncature (une page projetée par un autre fil entre deux temps), `kill` vers un numéro de fil, la place de /proc pour tous les fils ;
- des écarts à Linux : RUN_TO_PARITY et le temps virtuel d'une file vide dans l'EEVDF, l'ordre des erreurs de clone3, le nom d'un fil coupé au premier octet nul, les signaux du processus reconfiés quand un fil les bloque ou finit ;
- deux tests qui ne mordaient pas : « cible » (son ECHEC, maintenant cherché dans tout le journal de `make tests-qemu`) et « lignes » (qui ne peut pas prouver le verrou de la console sous QEMU sans accélération : écrit) ;
- `nc` pour `make tests-qemu` dans la CI, un journal de débogage committé par erreur, une vingtaine de commentaires devenus faux.

## 19. Sous-étape 6f réalisée : les signaux livrés, l'attente, les tubes, /proc à la demande

Dossier `06f-signaux/`, en quinze commits, d'après le plan écrit au début de son fil, mesuré sur Linux 6.18 par des sondes C et relu par un relecteur indépendant (`plan-6f.md` dans les fichiers du projet ; 26 constats intégrés avant de coder, dont 3 graves). **Le jalon :** le vrai Claude Code, `claude -p bonjour` (avec une fausse clé), va dans notre noyau jusqu'à l'appel de l'API et dit qu'il ne la trouve pas : « API Error: Can't reach the API server … (EAI_AGAIN) », faute de réseau avant 6g. Il passe dans une image à part (`make claude-p`, 28 s sous QEMU sans accélération).

1. **getrusage**, que `claude -p` demande dès son démarrage : le temps compté par tic comme le Linux d'une distribution, puis ajusté au temps exact de l'ordonnanceur (`cputime_adjust`) ; ru_maxrss, les fautes, les bascules.
2. **Les signaux en file, et leur siginfo** (le `sigpending` de Linux) : un temps réel en file autant de fois qu'envoyé, RLIMIT_SIGPENDING appliquée ; rt_sigqueueinfo, rt_tgsigqueueinfo, rt_sigtimedwait.
3. **La GDT de Linux** (choix de conception) : les mêmes sélecteurs (0x33 et 0x2B pour les programmes), que montre le contexte d'un gestionnaire.
4. **Le cadre de signal de Linux, octet pour octet** (choix de conception) : l'état x87/SSE/AVX en XSAVE ou FXSAVE avec ses mots magiques, l'ucontext, le siginfo ; SA_ONSTACK, SA_NODEFER, SA_RESETHAND ; `rt_sigreturn` qui vérifie tout ce qu'il recharge ; `sysretq` seulement quand RCX et R11 le permettent ; le `bad_iret` de Linux (un `iretq` qui faute est une faute du programme, jamais un arrêt du noyau) ; AT_MINSIGSTKSZ.
5. **Les fautes livrées à leurs gestionnaires**, avec le siginfo et le sigcontext que donne Linux (si_code, si_addr, trapno, err, cr2), mesurés faute par faute.
6. **Les appels interrompus reprennent** : les quatre codes internes de Linux (ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND, ERESTART_RESTARTBLOCK), SA_RESTART et `restart_syscall`, seulement pour le cadre d'un appel système.
7. **rt_sigsuspend et pause**, et le masque rendu au retour (`saved_sigmask`) ; `suspendre.c` imite la suspension des fils de JavaScriptCore (le moteur de Bun) par SIGPWR.
8. **Des files d'attente à entrées** (choix de conception) : les `wait_queue_entry` de Linux, exclusives ou non, la file sous son propre verrou ; l'eventfd devient un objet à lui, hors du verrou des fichiers.
9. **Le sondage des fichiers** (l'opération `poll` de Linux, la table de sondage, les entrées à rappel), et poll, ppoll, select, pselect6 dans l'ordre de `fs/select.c`.
10. **epoll attend vraiment** (choix de conception) : `fs/eventpoll.c` pas à pas, les éléments inscrits dans les files de leurs fichiers, la liste des prêts et sa liste de débordement, les epolls emboîtés, la recherche de boucles ; le fichier ouvert tient la liste de ses surveillants (le `f_ep`), qui meurent à son dernier close. Reste de 6d corrigé : les bits qu'accepte EPOLLEXCLUSIVE.
11. **Les tubes** : un anneau de pages avec la règle de fusion de Linux (`write(5000)` sur un tube presque plein rend 904), les attentes exclusives, SIGPIPE, O_DIRECT, F_SETPIPE_SZ, le compte des pages de l'utilisateur ; l'inode d'un tube dans le tmpfs.
12. **/proc fabriqué à la demande** (choix de conception) : plus aucune entrée gardée par processus ni par fil ; un numéro d'inode qui dit le genre, le processus et le fil. Écart de 6e corrigé : /proc/<tid> d'un fil secondaire se résout.
13. **/proc/<pid>/fd et les liens magiques** (`nd_jump_link`) : ce que lit Bun pour connaître son dossier courant ; un fichier effacé se rouvre, un tube se rouvre du côté demandé ; `exe` est lui aussi un lien magique, vers l'inode de l'exécutable.
14. **WASI poll_oneoff et sched_yield**.
15. **claude -p, le jalon**, dans son image à part ; il lui manque encore socket, copy_file_range, sendfile, fadvise64, socketpair et inotify_init1 (ENOSYS : il s'en passe, sauf du premier).

**Pendant l'étape :** la signature des commits a de nouveau cessé de marcher dans le conteneur ; les quinze commits ont attendu en patchs (un index git par commit, construit et vérifié à part), que David a créés et signés depuis WSL.

**Relecture de fond :** trois relecteurs indépendants (la livraison des signaux et la reprise des appels ; l'attente, poll, epoll, eventfd et les tubes ; /proc et la bibliothèque `fichiers`), 28 constats, chacun vérifié par une sonde sur l'hôte, les sources de Linux 6.18 ou une mutation. Repliés dans leurs commits :
- **un programme pouvait arrêter le noyau** : ouvrir `/proc/self/fd/N` d'un fichier qui a encore son nom (ou `/dev/stdout`, un dossier tenu en O_PATH) calculait son chemin en remontant des parents qu'un fichier n'a pas, et paniquait ; ce qu'on ouvre par un lien magique garde maintenant le chemin du fichier ouvert, comme Linux, et `/proc/<pid>/exe` devient lui aussi un lien magique ;
- **Reste de 6e** : `path_filestat_get` (WASI) lisait les attributs d'un objet qu'il ne tenait plus, qu'un autre programme pouvait effacer entre-temps (le noyau s'arrêtait) ;
- un lien magique sortait d'une résolution « sous » le dossier de départ (le confinement des programmes WebAssembly), et le rappel d'un epoll pouvait allouer, interruptions coupées, quand un fichier surveillé avait été fermé ;
- des écarts à Linux, mesurés : un signal ignoré qu'attend `rt_sigtimedwait` jeté à l'envoi ; le MXCSR rendu par un gestionnaire perdu quand le cadre ne demandait pas AVX ; `sigsuspend` qui rendait EINTR au lieu d'être refait quand un autre fil prenait le signal qui l'avait réveillé (l'ordre de `arch_do_signal_or_restart`, et une mutation le prouve) ; UC_STRICT_RESTORE_SS posé après un `iretq` refusé ; un sommeil échu rendu EINTR ; `rt_sigreturn` qui lisait le siginfo ; SIGSYS et SYS_USER_DISPATCH ; une poll_oneoff qui oubliait une horloge échue à côté d'un descripteur ; les attributs d'un dossier de /proc d'un processus parti ou zombie, task/<tid> immuable, le nombre de liens de /proc, `readlink` qui rendait 0 ;
- **Reste de 6d** : un `write` d'eventfd prend exactement 8 octets (Linux 6.6) ;
- une écriture dans un tube qui voyait partir le dernier lecteur entre deux pages, le `Drop` d'un tube qui prenait un Mutex sous un Verrou, un tube rouvert par son inode après qu'il a été redonné, `tubes sigpipe` qui dépendait de l'action héritée de SIGPIPE ;
- le code resté des entrées gardées de /proc (6b à 6e) retiré de `noyaufs`, l'ordre des verrous des fichiers et des processus écrit tel qu'il est, une quinzaine de commentaires devenus faux.

## 20. Sous-étape 6g réalisée : PCI, virtio-net, IPv4, UDP, ICMP et le DNS

Dossier `06g-reseau/`, en neuf commits, d'après le plan écrit au début de son fil, mesuré sur Linux 6.18, QEMU 8.2 et libslirp 4.7 par des sondes C et un noyau d'essai au brouillon, et relu par un relecteur indépendant (`plan-6g.md` dans les fichiers du projet ; 34 constats intégrés avant de coder, dont 2 graves). **Le jalon :** `claude -p bonjour` (avec une fausse clé) trouve maintenant l'adresse de l'API par le DNS (celui de slirp, qui relaie celui de l'hôte), puis s'arrête là où il le doit : « API Error: Connection refused … (ECONNREFUSED) », faute de TCP (6h). En 6f, il ne trouvait même pas l'adresse (EAI_AGAIN).

1. **Le bus PCI** : l'espace de configuration par les ports 0xCF8 et 0xCFC (le mécanisme n° 1, celui de l'i440FX ; ECAM viendra avec le vrai matériel), le parcours de `pci_scan_child_bus` en gardant ce qu'a attribué le BIOS, la mesure des BAR (décodage coupé, sauf celui du pont hôte : le `mmio_always_on` de Linux) ; le décodage dans `formats::pci`, testé sur l'hôte avec les espaces capturés de neuf fonctions de QEMU.
2. **Les vecteurs d'interruption à la demande, et MSI-X** (choix de conception) : de 0x40 à 0xEB, le premier libre (l'`irq_matrix` de Linux pour un processeur), un gestionnaire et son argument par vecteur, lus sans verrou ; MSI-X dans l'ordre de `msix_capability_init`. Pourquoi pas le fil INTx : sa ligne se lit dans la table `_PRT` de l'ACPI, en AML, un interpréteur entier.
3. **virtio, le transport PCI moderne** (virtio 1.x) : ses quatre structures, la poignée de main de la spécification, la maîtrise du bus que SeaBIOS laisse éteinte ; la carte virtio-net devient eth0, son lien suivi par l'interruption de configuration (le `linkwatch` de Linux).
4. **Les files de virtio** (choix de conception) : le format « split » avec EVENT_IDX, et ses barrières (un vrai `fence` entre l'écriture d'un index et la lecture de l'index d'événement de l'autre) ; les paquets (le `sk_buff`), les interfaces (la `net_device`) ; la tâche du réseau fait aussi le travail de NAPI (le NAPI « threaded » de Linux), 64 trames par passage.
5. **Ethernet, IPv4, et la configuration par DHCP** (choix de conception, deux fois) : la configuration faite par le noyau au démarrage (le `ip=dhcp` de Linux, `ipconfig.c` : ses messages, ses délais, la MTU posée, les DNS dans `/proc/net/pnp`, dont `/etc/resolv.conf` est un lien) ; les règles de la pile dans une bibliothèque `inet/`, sans `unsafe`, testée sur l'hôte à l'horloge simulée ; l'entrée d'IPv4 et ses martiens ; /proc/net (pnp, route, dev).
6. **ARP, les voisins** : la machine à états de Linux (`neighbour`, ses délais, sa file), les règles d'`arp_process` et de `__neigh_update` (le locktime, l'ARP gratuit), /proc/net/arp.
7. **Les sockets, et UDP** (choix de conception) : la socket à deux étages de Linux, deux verrous (un `Verrou` pour ce que touche la tâche du réseau, un `Mutex` pour les appels) ; bind, connect, le port éphémère, sendto/recvfrom, sendmsg/recvmsg avec IP_PKTINFO, sendmmsg/recvmmsg, les options, poll et epoll ; l'interface de boucle `lo`, dont la file est vidée dans le contexte de qui envoie (le softirq de Linux) : un datagramme envoyé à soi-même est là quand `sendto` revient ; les routes de `ip_route_output` (0.0.0.0, une source de la boucle qui ne sort pas, SO_DONTROUTE).
8. **ICMP, ses erreurs, et les sockets de ping** : l'écho, les erreurs envoyées comme `__icmp_send` (et sa limite globale), les erreurs rendues aux sockets (ECONNREFUSED, IP_RECVERR et la file d'erreurs) ; les sockets de ping (SOCK_DGRAM, IPPROTO_ICMP) sans être root.
9. **Le DNS, par la glibc** : rien de neuf dans le noyau ; un serveur DNS dans le programme de test (`linux/dns.c`) qui répond de travers, `api.anthropic.com` trouvé par le DNS de slirp, et sans serveur, EAI_AGAIN tout de suite (l'ICMP « port injoignable » revient par `lo`).

**Pendant l'étape :** la signature des commits n'a pas marché de toute l'étape dans le conteneur, même après le déverrouillage de 1Password : les commits ont attendu en patchs, à créer et signer depuis WSL.

**Relecture de fond :** trois relecteurs indépendants (le matériel ; la pile sous les sockets ; les sockets), chacun avec les sources de Linux 6.18 et sans mes conclusions, 50 constats (aucun grave, 7 moyens), chacun vérifié par une sonde sur l'hôte et dans QEMU, une capture de trames, les sources ou une mutation. Repliés dans leurs commits :
- **une adresse de `lo` sortait par eth0** : une socket liée à 127.0.0.1 (ou un IP_PKTINFO de source 127.0.0.1) envoyait vers le dehors un paquet de source 127.0.0.1 ; Linux rend EINVAL (`__mkroute_output`) ;
- **`msg_controllen` n'était pas borné** : jusqu'à 2 Gio alloués dans le tas du noyau à chaque sendmsg ; Linux refuse au-delà d'`optmem_max` (ENOBUFS) ;
- **ce qui part par `lo` arrivait trop tard** (au passage suivant de la tâche du réseau) ; maintenant livré avant le retour de l'appel, comme Linux ;
- une fausse alerte « memoire rendue » (un paquet encore dans la file d'un voisin muet, que le repos du réseau ne regardait pas) ;
- le décodage du pont hôte coupé pendant la mesure des BAR (risqué sur un vrai PC) ; une requête ARP qui ne nous vise pas ignorée (une passerelle qui change d'adresse matérielle coupait le trafic jusqu'à 53 s) ; la MTU donnée par le DHCP lue, jamais posée ;
- 43 constats mineurs : des écarts à Linux mesurés (les genres ICMP qui sont des erreurs, IP_PMTUDISC_DONT, la destination 0.0.0.0, la diffusion de `lo`, l'ordre des erreurs d'accept4 et de connect, IP_PKTINFO, SO_DONTROUTE, l'identifiant IP, une socket de ping liée à une diffusion…), une BAR « tous les bits à 1 », une mise en service ratée qui perdait 256 pages, deux tests qui ne mordaient pas (révélés par neuf mutations), une vingtaine de commentaires faux.

## 21. Relecture globale du projet (2 novembre 2026)

Pendant 6h, à la demande de David, une relecture du projet entier face à ses volontés de départ (le rapport : `relecture-globale.md`, dans les fichiers du projet). Le fond tient : aucune crate externe, un chargeur maison, des bibliothèques sans `unsafe`, des choix calqués sur Linux et justifiés en commentaire. Ses corrections sont des commits « Reste de 6g », faits pendant 6h ; ses trois recommandations, acceptées par David (« c'est bon »), sont ci-dessous.

1. **Aucune allocation qui panique** (choix de conception) : une allocation infaillible (`Box::new`, `push`, `format!`...) fait paniquer la machine quand le tas est plein, et depuis TCP un client du dehors peut pousser le noyau à allouer. Comme Rust pour Linux, le noyau n'alloue plus que par des fonctions qui rendent une erreur (`faillible.rs`), avec notre propre `Arc` (`partage.rs` : Rust stable n'en a pas de faillible) ; `cargo clippy`, lancé par `make`, refuse les autres (`noyau/clippy.toml`). Écartés : recompiler `alloc` sans elles (un compilateur nightly), une revue à la main (elle se relâcherait). Les bibliothèques restent à faire (« Reste à faire »).
2. **Le marqueur `UNIPROCESSEUR`** : chaque endroit qui suppose un seul processeur le dit par une ligne qui commence par ce mot (23 endroits) ; `grep -rn UNIPROCESSEUR` donne la liste de ce que 6j reprendra.
3. **`unsafe`, vérifié par le compilateur** : la règle « cantonné aux quelques fonctions qui touchent le matériel » était fausse, la pratique bonne (240 `unsafe`, presque tous justifiés, aucun dans les appels système). Réécrite (section 9), elle est maintenant vérifiée : `#![deny(unsafe_code)]` en tête de `main.rs`, et un `#[allow(unsafe_code)]` pour chaque module d'abstraction, rangé par famille (le matériel, la mémoire physique, les copies vers les programmes, la synchronisation, la bascule) : un `unsafe` glissé ailleurs ne compile plus. Clippy exige le commentaire `SAFETY:` de chaque bloc (d'où `SAFETY:` sans l'espace du français : clippy ne reconnaît que celui-là). La bibliothèque `wasm` interdit `unsafe`, comme les autres. Trois fichiers qui n'étaient pas des modules d'abstraction en sont sortis : les pages d'un tube sont des `pages::Page` (une page qu'on possède seul, rendue quand on la lâche), l'archive de démarrage est prêtée le temps du déballage (`demarrage::deballer_archive`), et la lecture des exceptions flottantes est passée dans `sse.rs`.
4. **La feuille de route complétée** (choix de conception) :
   - le **multiprocesseur** devient une sous-étape, **6j, juste après 6i** : une fois la première réponse de Claude obtenue, avant le terminal, `fork` et le disque, qui ajouteront beaucoup de code synchronisé. Linux est passé au multiprocesseur en 2.0 (1996) avec un « grand verrou », et a mis quinze ans à s'en défaire : plus on écrit de code pour un seul processeur, plus le retour coûte. Les sous-étapes suivantes prennent la lettre d'après (le terminal 6k, `fork` et le shell 6l, le disque 6m, le durcissement 6n) ; les dossiers des étapes passées gardent les lettres de leur époque. Écartés : le multiprocesseur à la fin de l'étape 6, ou après Claude Code (davantage de code à reprendre) ;
   - le **verrou du processus qui dort** (le `mmap_lock` de Linux) en 6i : il coupe encore les interruptions, et les tics perdus pendant un gros `munmap` retarderaient les minuteries de TCP (Bun rend d'un coup 54 Mio par `madvise`) ;
   - **plus tard** : un compilateur WebAssembly dans le noyau, la voie Nebulet du format natif, restée sans étape depuis la 4, puis les flottants du processeur ; et les pilotes du vrai matériel, la deuxième volonté de départ (section 2), que la feuille de route ne citait pas.
5. **La documentation** : « Reste à faire » en deux listes, les dettes chacune avec son étape et les écarts voulus avec Linux à part (section 23) ; le README, arrêté à 6d, à jour, et désormais dans chaque fin d'étape (skill `fin-d-etape`) ; trois règles de `CLAUDE.md` écrites comme elles se pratiquent (un choix de conception dans le message de son commit, une correction tardive dans l'étape courante seulement, les dossiers de l'étape 2). Les tests du démarrage qui ne pouvaient pas échouer ont été corrigés dès les premiers commits de 6h (« Outillage » : `verifier.sh` échoue sur tout ECHEC ou PANIQUE).

## 22. Sous-étape 6h réalisée : le générateur aléatoire, TCP, AF_UNIX et les sockets de WASI

Dossier `06h-tcp/`, en dix commits (entre lesquels se sont glissés ceux de la relecture globale, section 21), d'après un plan mesuré sur Linux 6.18, libslirp 4.7 et `claude -p` lui-même, et relu par un relecteur indépendant au début de son fil (`plan-6h.md` dans les fichiers du projet ; 32 constats intégrés avant de coder, dont 2 graves). Le commit de TCP qu'il prévoyait pour la fiabilité et le débit a été coupé en deux, comme le permettait sa section des risques. **Le jalon :** `claude -p bonjour` va jusqu'à l'API : il trouve son adresse par le DNS, s'y connecte par notre TCP, Bun y fait son TLS, et l'API répond à la fausse clé « Invalid API key ». Un programme C télécharge aussi une page HTTP de 4 Mio d'un serveur que QEMU lance sur l'hôte, et 64 Mio passent d'un fil à l'autre par `lo` en 1,1 s sous QEMU sans accélération.

1. **La bibliothèque `crypto/`** : ChaCha20, BLAKE2s et SipHash, sans `unsafe` ni dépendance, testés sur l'hôte contre les vecteurs des RFC et deux implémentations indépendantes, rejoués par le noyau au démarrage (comme les auto-tests de Linux).
2. **Le générateur aléatoire de Linux** (choix de conception) : celui de `drivers/char/random.c` depuis 5.17 plutôt qu'un ChaCha20 réensemencé par RDRAND, parce qu'il est le seul qui marche sans RDRAND (le processeur de l'étape, Nehalem, n'en a pas) : un réservoir BLAKE2s, un ChaCha20 à effacement rapide de la clé, prêt à 256 bits crédités ; les sources (RDSEED, RDRAND, les interruptions des périphériques, la gigue du compteur de cycles quand un programme attend) ; `getrandom`, `/dev/random`, `/dev/urandom`, `/proc/sys/kernel/random`. Les identifiants IP passent par lui (`ip_idents` : une dette de 6g remboursée).
3. **virtio-rng** : le générateur de l'hyperviseur, qui rend le nôtre prêt avant le réseau sur la machine de l'étape.
4. **Trois mécanismes de Linux que TCP demande** : les échéances du réseau (une liste triée réservée d'avance, plutôt que la roue de minuteurs de Linux, faite pour des centaines de milliers de connexions), le contexte réseau (la règle du softirq : ce qui part par `lo` sous un verrou court n'est livré qu'à sa sortie) et la fermeture différée (le `task_work` du dernier `close`).
5. **TCP, les connexions** (choix de conception, deux fois) : la machine à états dans la bibliothèque `inet` (testée sur l'hôte), le noyau autour ; la possession d'une socket (le `lock_sock` de Linux et sa file, traitée sans le verrou court) ; les filles d'une écoute, de petites valeurs dans sa file jusqu'à `accept`, la socket ne naissant que dans l'appel système ; TIME_WAIT, une petite entrée de 60 s.
6. **TCP, la fiabilité** : le RTO de Jacobson tel que l'écrit Linux, Karn, l'abandon de `tcp_write_timeout`, Reno, NewReno et PRR, la file hors d'ordre, les ACK retardés, la sonde de fenêtre ; un simulateur relie deux connexions par un lien qui perd, duplique, retarde et réordonne, et vérifie des invariants (20 000 essais passés une fois, 200 à chaque `make tests-hote`).
7. **TCP, le débit et les options** : l'échelle de fenêtre, Nagle et Minshall, TCP_CORK, le keepalive, l'octet urgent, SO_SNDBUF qui grandit, SO_LINGER, TCP_INFO, `/proc/net/tcp`, la mémoire de TCP de toute la machine (`tcp_mem`).
8. **AF_UNIX** : les trois sortes, la taille vraie des paquets de Linux comptée contre l'émetteur, les connexions faites dans `connect`, les noms (chemin, abstrait, automatique), `/proc/net/unix` ; `claude -p` en ouvre vingt paires à son lancement.
9. **Les sockets de WASI** : `--tcplisten=` dans `/etc/demarrage`, l'écoute créée par le lanceur comme celui de wasmtime, `sock_accept`, `sock_recv`, `sock_send`, `sock_shutdown`, `poll_oneoff` qui attend vraiment, `fd_fdstat_set_flags` ; un programme WebAssembly sert deux clients.
10. **Une page HTTP** : un serveur lancé par QEMU pour chaque connexion (`guestfwd=...-cmd:`), sans Internet ni port ouvert sur l'hôte, et un client C qui vérifie chaque octet.

**Pendant l'étape :** la signature des commits (1Password, par l'agent SSH de Windows) a marché par moments : son accord expire après quelques minutes, sa demande arrive dans une notification du systray, et un redémarrage de 1Password l'a réparée. Les commits ont donc été signés par paquets, quand David était là. Un plantage rare de `claude -p` sous QEMU, déjà là en 6g, a fini par trouver son explication : c'était QEMU (plus bas).

**Relecture de fond :** trois relecteurs indépendants (l'aléa et les échéances ; TCP ; AF_UNIX, WASI et la page HTTP), chacun avec les sources de Linux 6.18 et sans mes conclusions : 48 constats (3 graves, 20 moyens, 25 mineurs), chacun prouvé par une sonde lancée sur l'hôte puis dans notre noyau, par un test ou par la ligne de Linux. Aucun ne cassait `claude -p`. J'en proposais trois en écart ; David a demandé de tout corriger. Chaque correction est repliée dans le commit qui avait écrit le code fautif, sous la forme qu'il avait alors, avec le test qui la montre :
- **les trois graves** : `accept4` perdait la connexion quand il échouait après l'avoir prise (EMFILE, ENFILE, une adresse de retour fautive) ; Linux réserve le descripteur et le fichier avant d'accepter, nous aussi maintenant, en TCP, en AF_UNIX et dans `sock_accept` ; une fille TCP en CLOSE_WAIT (un client HTTP/1.0 qui envoie sa requête et son FIN avant l'`accept`) n'était jamais signalée par `poll` ; une course entre la recherche d'un segment et sa livraison pouvait faire relivrer un segment à l'écoute sous son propre verrou ;
- **parmi les moyens** : la clé du tirage d'avant l'effacement restait dans l'état pendant la copie vers le programme (Linux l'écrase exprès) ; deux courses d'échéances (ARP, et le réveil de la tâche du réseau) ; `recv` rendait la fin du flux quand seul l'octet urgent attendait ; une fille n'héritait pas des options de son écoute ; après un `connect` refusé, ni `connect` ni `listen` ne marchaient plus ; deux pairs désynchronisés s'échangeaient des ACK sans fin (Linux en limite un toutes les 500 ms) ; un MSS de 1 découpait tout en segments d'un octet (CVE-2019-11479) ; une socket reconnectée après un TIME_WAIT perdait sa connexion 60 s plus tard ; aucune limite à la mémoire de TCP de toute la machine (`tcp_mem`) ; le verrou des lecteurs d'AF_UNIX tenu pendant l'attente ; `poll` d'un datagramme AF_UNIX connecté qui n'était pas réveillé quand la file pleine de son destinataire se vidait (le relais de Linux, `unix_dgram_peer_wake_relay`) ; et 23 mutations du code qui survivaient aux tests, chacune tuée maintenant par un test ;
- **un défaut trouvé après la relecture**, en préparant la suite : l'échelle de fenêtre proposée était celle d'un Linux plus ancien (7, d'après un `tcp_rmem[2]` de 6 Mio) ; Linux 6.18 la calcule d'après la mémoire de la machine et SO_RCVBUF (`tcp_init`, `tcp_select_initial_window` : 8 sur la machine de l'étape, 10 sur l'hôte), et l'option part même pour une échelle de 0 ;
- **les mineurs** : des valeurs et des comportements de Linux (TCP_LINGER2, TCP_DEFER_ACCEPT, TIME_WAIT, les masques de `poll`, FIONREAD, SO_RCVLOWAT, IP_TTL et IP_TOS, les noms d'AF_UNIX et leur taille vraie...), et des commentaires périmés.

Le repli a été lourd : 2 600 lignes de corrections dans des commits que les suivants avaient réécrits. Il s'est fait par la plomberie de git, sans rien signer en route, puis toute la chaîne a été re-signée d'un coup. Quelques corrections sont allées au commit qui apporte leur machinerie plutôt qu'à celui du code d'origine (ce qui manquait n'était pas un défaut) : la limite des ACK avec l'heure de la fiabilité, `tcp_mem` et SO_RCVLOWAT avec le débit et les options. Chaque commit replié a été construit et vérifié dans QEMU, et l'arbre final est identique à celui qui avait été vérifié avant le repli.

**La suite, avant de clore l'étape (3 et 4 novembre 2026).** David a voulu « le plus nickel possible » : tout ce que le plan de 6h repoussait est fait dans 6h plutôt qu'écrit en dette. Vingt et un commits de plus : `tcp_rmem`, `tcp_wmem` et l'ISN de Linux 6.18 ; les segments acceptés comme `tcp_sequence` et `tcp_check_req` ; TIME_WAIT dans `inet` ; la file de retransmission ; les horodatages et PAWS ; SACK, D-SACK et RACK ; la sonde de fin de rafale (TLP) ; F-RTO et l'annulation ; CUBIC et HyStart, le débit calculé ; la réception qui s'ajuste (DRS, `tcp_clamp_window`, l'élagage et la fonte des files) ; TSQ et l'autocork ; la fragmentation et le réassemblage d'IPv4 ; la MTU du chemin (les exceptions de route, comme `fib_nh_exception`) ; TCP_DEFER_ACCEPT et /proc/sys/net ; TCP_INFO jusqu'au bout (le débit livré, les chronomètres) ; les blocs TCP dans le tas, la pile du noyau mesurée à chaque fin de programme ; SCM_RIGHTS et le ramasse-miettes d'AF_UNIX (par composantes, comme `net/unix/garbage.c`), SCM_CREDENTIALS, MSG_OOB ; la vraie roue des minuteurs de `kernel/time/timer.c`, à la place de la liste triée (crate `roue`) ; `tcp_write_wakeup` pour la sonde de fenêtre.

**Deuxième relecture de fond :** trois relecteurs indépendants sur ces vingt et un commits, avec les sources de Linux 6.18 : 66 constats (7 graves, 27 moyens, 32 mineurs), tous corrigés. Les graves : une fille gardait l'heure de son SYN-ACK (après 15 min de service, ETIMEDOUT au deuxième RTO) ; les blocs SACK n'étaient pas triés (un faux réordonnancement, qui déréglait RACK jusqu'à la fin de la connexion) ; une fille n'héritait pas de SO_REUSEADDR (un serveur ne redémarrait pas tant qu'une de ses connexions vivait) ; `recv` rendait une erreur au lieu de la fin après un FIN puis un RST ; MSG_PEEK | MSG_TRUNC retirait les octets ; un écrivain AF_UNIX bloqué dont le pair ferme recevait SIGPIPE au lieu d'ECONNRESET ; `shutdown` d'une écoute AF_UNIX ne réveillait pas `accept`. Un auto-test de la MTU passait sans rien vérifier quand il ne pouvait pas se dérouler : un `?` sur une Option, qui rendait « pas d'erreur ». Deux constats que je proposais d'écrire comme écarts ont été corrigés à la demande de David (« tous les problèmes identifiés doivent avoir leur solution ») : **SO_PEEK_OFF** sur TCP, UDP et AF_UNIX, et **F_SETOWN et ses variantes, F_SETSIG, SIGURG et O_ASYNC** (`noyau/src/asynchrone.rs`, `linux/proprietaire.c`), avec getpgrp, getpgid et getsid. Seuls deux écarts restent, là où c'est Linux qui se trompe (voir plus bas).

**Les mutants :** `cargo mutants` sur tous les modules de TCP en laissait passer un tiers (`tcp.rs` seul : 1 467 mutants, près de 390 survivants), et une dizaine sur la roue : les bornes n'étaient pas regardées. Des tests internes aux modules (`#[cfg(test)]`, dans chaque module, et pour `tcp.rs` `inet/src/tcp/essais_*.rs` : ce que lit le noyau, les segments reçus, les ACK retardés, les minuteurs, l'émission) posent l'état et lisent le résultat, avec les valeurs des formules de Linux ; le C de `win_minmax.c` et de `tcp_rtt_estimator`, recopié dans les tests, sert de référence au hasard ; `tests/reception_au_hasard.rs` vérifie les invariants de la réception à chaque segment. Sur `tcp.rs`, il reste 26 survivants, et 5 sur la roue, lus un à un et équivalents : un `|` changé en `^` sur des bits disjoints, une borne où l'égalité donne la même valeur, une action qui ne fait rien sur une file vide. L'équivalence n'est prouvée que par cette lecture. Un survivant a montré du code qui ne servait à rien : le plafond de 500 ms d'un ACK retardé, que `icsk_delack_max` ramène aussitôt à 200 ms, y compris chez Linux.

**Le plantage rare de `claude -p` : un bogue de QEMU (5 novembre 2026).** Une faute de segmentation dans Bun, ou un SIGABRT, à peu près une fois sur quarante, plus souvent quand la machine était chargée (pourquoi : pas mesuré), déjà en 6g. Un noyau instrumenté ne trouvait rien : ni page projetée deux fois, ni cadre libre encore projeté, et les registres montraient des valeurs absurdes dans du code JavaScriptCore. Ce qui a tranché, dans l'ordre :
- **le témoin** : le même binaire sous le vrai Linux 6.8, sur la même machine QEMU (TCG, Nehalem, 2 Gio) et sous la même charge : deux échecs sur une centaine d'essais, dont ce message de JavaScriptCore : « Unexpected code block in DFG->FTL tier-up: ...BaselineFunctionCall » : du code DFG avec, dans son cadre, le CodeBlock de la version Baseline. Directement sur l'hôte, sans QEMU, sur un cœur partagé avec huit boucles de calcul : 800 essais, aucun échec. Ni notre noyau, donc, ni Bun ;
- **le relevé** : le noyau gèle à la première faute d'un programme, QEMU relève ses 2 Gio (`pmemsave`), et on lit l'espace du programme en parcourant ses tables de pages. La faute : un appel direct de code DFG, `movabs r11, <CodeBlock> ; mov [rsp], r11 ; call <cible>`. En mémoire, le `movabs` porte le bon CodeBlock ; dans le cadre de l'appelé, il y a 0, sa valeur d'avant le lien ; le `call`, lui, va à la bonne cible. Ce `movabs` commence deux octets avant la fin d'une page. Les trois captures ont leur adresse de retour juste après une frontière de page (`...ab011`, `...93011`, `...f5004`) : l'opérande du `movabs`, ou le déplacement du `call`, était sur la page suivante ;
- **la lecture** : QEMU garde, pour chaque page, la liste des blocs traduits qui s'y trouvent, et invalide ceux qu'une écriture touche. `tb_record` et `tb_remove` (`accel/tcg/tb-maint.c`, 8.2.2) ont une erreur de frappe, `pindex1 = paddr0 >> TARGET_PAGE_BITS` : la deuxième page d'un bloc à cheval n'est jamais enregistrée. Le compilateur à la volée patche ses appels directs (`DirectCallLinkInfo::setCallTarget`) : le bloc périmé garde l'ancienne valeur à côté de la nouvelle. Corrigé en amont dès la 8.2.3 ; le paquet d'Ubuntu 24.04, le nôtre et celui de la CI, en est resté à la 8.2.2 ;
- **la preuve** : `linux/autocode.c` réécrit l'opérande d'un `movabs` posé à cheval : sur l'hôte, 0 lecture périmée sur 1000 ; dans QEMU 8.2.2, sous notre noyau comme sous Linux, 1000 sur 1000 ; dans la même 8.2.2 corrigée de cette seule ligne, 0. Et `claude -p` sous ce QEMU : 40 essais sur 40 sous notre noyau, 40 sur 40 sous Linux.

D'où QEMU 8.2.10 compilé dans le Dockerfile et la CI (`.devcontainer/construire-qemu.sh`), et `linux/autocode` à chaque démarrage, qui dit le bogue au lieu d'un plantage rare. La leçon pour les prochains : devant un plantage qu'on ne reproduit pas à volonté, le témoin d'abord (le même programme, le vrai Linux, la même machine), avant d'instrumenter le noyau.

**La CI rouge depuis 6d (6 novembre 2026).** En regardant la CI après le push de 6h : elle échouait sur `main` à chaque envoi depuis le 26 octobre, et personne ne l'avait vu. Le journal du dernier run (celui de `baacc67` ; ceux d'avant n'ont pas été lus) : `linux/memoire`, lancé sur l'hôte, y dit ECHEC pour la dernière page de l'espace d'un programme, dans toutes les étapes de 6a à 6h. Pour Linux à cinq niveaux de tables (LA57), `0x7ffffffff000` est une page comme une autre, et elle était écrite en dur. Le même témoin que pour QEMU l'a montré : le vrai Linux 6.8 sous QEMU, `-cpu qemu64,+la57` : ces deux mêmes échecs ; `-cpu Nehalem` : aucun. Que les machines de GitHub soient en LA57 s'en déduit, sans mesure directe (leur journal ne le dit pas). Le test demande maintenant au noyau où est sa dernière page. Comme `make tests-hote` s'arrêtait là, le reste des tests sur l'hôte n'a pas tourné sur ces runs. Le run suivant a confirmé `memoire`, et montré `linux/fichiers`. Les notes de l'image de GitHub donnent son noyau, Linux 7.0.0-1017-azure, alors que nos tests sur l'hôte ont 6.18 pour référence. Plutôt qu'un push par écart, le paquet exact de ce noyau sous QEMU (`-cpu max`, une carte virtio, les mêmes programmes dans un tube, l'utilisateur 1000) a fait passer d'un coup les `tests-hote` des huit étapes. Cinq programmes, cinq raisons :
- `fichiers` : avec la table pleine, le chemin nul ou vide rend EMFILE sous 7.0 (6.18 et notre noyau : EFAULT, ENOENT) ;
- `signaux` et `gestionnaires` : les drapeaux de la pile de secours viennent de nos ancêtres, et exec n'y touche pas ; SS_DISABLE si l'un d'eux était un fil sans pile de secours ;
- `gestionnaires`, une erreur du test : il copiait 1792 octets du cadre, et MAGIC2 est plus loin dès qu'il y a PKRU ou AVX-512 ; les composants de XSAVE suivent aussi le processeur ;
- `tubes` : O_NOTIFICATION_PIPE crée un tube là où CONFIG_WATCH_QUEUE est compilé (WSL : ENOPKG, comme nous) ;
- `clone` : une adresse de TLS interdite à quatre niveaux, permise à cinq (LA57).
- `attente`, vu au run suivant : `select` au-delà de la table des descripteurs supposait 128 cases, alors qu'elle vient aussi des ancêtres. Un numéro 300 hérité le reproduit ici ; que la CI en hérite ainsi se déduit, sans mesure. Sur l'hôte, le test se fait désormais dans un petit-fils à table neuve ;
- `systeme` : « aucune faute majeure » comptait aussi les pages du programme lui-même, s'il n'est pas encore dans le cache (vu après le redémarrage du conteneur, reproduit en vidant le cache de ce fichier). Seul notre noyau, où tout est en mémoire, y est tenu.

Dans notre noyau (`/etc/bonjour.txt` le dit à ces programmes), chaque vérification reste aussi stricte qu'avant ; seul l'hôte a droit à la variante. La leçon : regarder la CI après chaque push (`fin-d-etape`).

## 23. Reste à faire

Deux listes, depuis la relecture globale (section 21) : les **dettes**, à rembourser, chacune avec l'étape qui le fera, ou ce qui la déclenchera ; puis les **écarts voulus avec Linux**, permanents, chacun justifié.

### Les dettes

**6i** (`claude -p`)

- **Le verrou du processus coupe les interruptions** : un munmap ou la fin d'un programme qui a touché des centaines de Mio rend ses cadres d'un trait, et des tics d'horloge se perdent ; il sérialise aussi les fautes de page de tous les fils. Un verrou qui dort, en lecture et écriture (le `mmap_lock` de Linux).
- **Ce que `claude -p` demande encore** : `copy_file_range`, `sendfile`, `fadvise64`, `inotify_init1`, qui rendent ENOSYS et dont il se passe (copies par read et write, pas de surveillance des fichiers). Sa vérification « memoire rendue » (`make claude-p`) échoue, à raison : les fichiers qu'il laisse dans HOME restent dans le tmpfs ; mieux : faire lister par `arbre` ce qu'il y laisse, et vérifier que l'écart de mémoire correspond exactement.
- **Le dossier courant du lanceur** est `/`, que l'utilisateur 1000 ne peut pas écrire (à revoir pour `claude`).

**6j** (le multiprocesseur)

- **Tout ce que disent les lignes `UNIPROCESSEUR`** du code, dont les listes par processeur du tas, et un ordre total des verrous des fichiers et des processus (deux ordres coexistent depuis /proc à la demande, 6f, sans danger sur un seul processeur : vfs.rs).
- **Préempter en rendant un verrou** (Linux le fait) : chez nous, un réveil fait dans le noyau ne prend effet qu'au retour vers l'anneau 3 ou au tic suivant. Avec le compte de préemption que demandera le multiprocesseur.
- **Le test « lignes »** ne peut pas prouver le verrou des écritures de la console sous QEMU sans accélération (TCG ne livre l'horloge qu'entre deux blocs traduits) : avec plusieurs processeurs, ou sur un vrai processeur.
- **`unsafe` dans epoll.rs et sondage.rs**, pour inscrire leurs entrées de rappel dans les files d'attente : une interface sûre dans `attente.rs`, une entrée qui garde sa file et se retire d'elle-même quand on la lâche (celles d'epoll ne gardent pas leur fichier, comme chez Linux : il les retire en fermant), avec la reprise d'`attente.rs`.

**6k** (le terminal)

- **Console non bloquante.** Le port série fait attendre activement (87 µs par octet sur du vrai matériel) : un pilote à interruptions et une file d'attente, comme le tty de Linux.
- **La console écrit au plus 1024 octets par appel**, et ld-linux ne reprend pas une écriture courte (`ld.so --help` est coupé ; stdio et Bun reprennent). Linux n'écrit jamais court sur un terminal, mais il peut attendre et être interrompu.
- **Les signaux** (6f) : un programme qui devrait s'arrêter (SIGSTOP, SIGTSTP) est terminé, faute de contrôle des tâches pour lui envoyer SIGCONT (6k, 6l) ; une attente que rien ne finira (plus aucune tâche prête ni minuterie) arrête les programmes qui dorment, par SIGKILL et en le disant, faute de terminal pour les interrompre.

**6l** (`fork`, `execve`, un shell)

- **Le lanceur `/etc/demarrage`** cède la place à un vrai `/init` et à un shell avec `fork` et `execve`. Une limite de temps : le programme la pose (setrlimit), et le shell aura `ulimit -t`.
- **Les fils** : un processus neuf (fork, vfork), CLONE_PIDFD, set_tid, CLONE_INTO_CGROUP, CLONE_CLEAR_SIGHAND rendent ENOSYS, un espace de noms EPERM (CLONE_NEWUSER compris, que Linux permet) ; CLOSE_RANGE_UNSHARE est refusé avec plusieurs fils (la table est au processus) ; la base de GS n'est pas sauvée par tâche (arch_prctl refuse ARCH_SET_GS).
- **MAP_SHARED d'un fichier** reste refusé : il faudra écrire les pages dans le fichier, et les retrouver dans chaque processus qui le projette (la carte inverse `i_mmap`). Pour la même raison, raccourcir un fichier ne retire ses pages que des projections du processus en cours : un autre programme qui le projette (`&`) y lit l'ancien contenu au lieu d'un SIGBUS.
- **Les verrous de fichiers** (fcntl, flock) sont vérifiés mais toujours accordés : deux programmes lancés par `&` ne s'excluent pas. Une vraie table des verrous ; et l'O_TRUNC de `path_open` (WebAssembly) avec le verrou d'écriture de l'inode.
- **Le tueur OOM** tue le programme qui faute, pas le plus gros : avec plusieurs programmes à la fois, un petit peut payer pour un gros.
- **Les limites de ressources** autres que celle des descripteurs sont gardées et rendues, pas appliquées (la pile reste à 8 Mio quoi qu'on demande).
- **`mknodat`** (259) est encore un appel inconnu.
- **Les signaux**, le reste : ni `signalfd`, ni `timerfd`, ni minuteries de processus (`setitimer`, `alarm`, `timer_create`) ; pas de fichier core ; le pid 1 n'a pas le statut à part de Linux ; un signal envoyé au processus est pris par le premier de ses fils qui retourne vers l'anneau 3 sans le bloquer (Linux le laisse au fil qu'il a choisi et prévenu, `complete_signal`).

**6m** (le disque)

- **Une couche VFS**, avec des opérations par système de fichiers (le trait `Arbre`/`Monte` couvre la résolution, pas les données), que demandera ext2 ; et un dentry au tmpfs : le texte d'un lien de /proc/<pid>/fd et de maps garde le chemin de l'ouverture, et « (deleted) » se décide par le nombre de liens de l'inode, quand Linux suit le nom ouvert (un renommage s'y voit, et « (deleted) » pour un nom effacé dont un autre lien physique garde l'inode).
- **`unsafe` dans vfs.rs**, qui lit et écrit les pages des fichiers par leur numéro de cadre (celui que donne le tmpfs) : un type qui les possède, avec cette couche.

**6n** (le durcissement)

- **Pages globales** (CR4.PGE), KPTI, PCID ; **le vecteur auxiliaire** n'a pas AT_SYSINFO_EHDR (le vDSO), ni AT_RSEQ_* ; `rseq` rend ENOSYS : la glibc a un repli pour chacun.
- **Les allocations des bibliothèques.** Le noyau n'en a plus aucune qui panique (6h : `faillible.rs`, notre `Arc`, et `cargo clippy` qui le vérifie). Les bibliothèques qu'il embarque en gardent : `wasm` (plus d'une centaine d'appels, et le module d'un programme dans l'`Arc` de `alloc`), `fichiers` (environ 70), `formats` (environ 35), `inet` et `zones` (une dizaine chacune). Le même passage, et la même règle de clippy pour chacune, `fichiers` et `inet` d'abord (un programme ou un client du dehors peut les faire allouer).
- **La carte des zones et la réserve** : la carte d'un programme vient du tas du noyau, qui peut puiser dans la réserve (3 Mio au plus, 5 le temps de l'agrandir) ; Linux prend ses `vm_area_struct` au-dessus du seuil. Avec les allocations de `zones`.

**Avec les pilotes du vrai matériel** (« Plus tard »)

- **PCI** : seul le premier pont hôte est parcouru ; les bus d'un autre (un serveur à plusieurs complexes racines, l'expandeur `pxb` de QEMU) se trouvent par l'ACPI (l'AML de chaque pont hôte), et l'espace de configuration de PCI Express par ECAM (la table MCFG).
- **virtio-net** veut trois entrées MSI-X (la configuration, une par file) ; une carte qui en a moins reste éteinte, là où Linux se replie sur un vecteur partagé puis sur INTx (dont la ligne se lit dans la table `_PRT` de l'ACPI). Aucune carte de QEMU n'en a moins, sauf demandé.
- **L'APIC n'est vérifié que sous QEMU**, en xAPIC ; x2APIC (que TCG n'imite pas) fait revenir au 8259. Non vérifiés faute de pouvoir les imiter : `sysretq` avec un SS nul après une bascule sur AMD (le `X86_BUG_SYSRET_SS_ATTRS` de Linux), une adresse ACPI au-delà de MAXPHYADDR (Linux la refuse).
- **NMI pendant le passage éclair en mode protégé du chargeur** : non masqué (Linux le masque par le port 0x70 pour son passage définitif). Risque infime, à revoir si un essai sur vrai matériel le montre.
- **Démarrage sur clé USB : réserver un BPB factice dans le secteur 0.** Pour une clé, certains BIOS « émulent » une disquette et croient trouver au début du secteur 0 un BPB (BIOS Parameter Block, la description d'un système de fichiers FAT) : ils réécrivent les octets 3 à 0x5A avec leurs propres valeurs, ce qui écraserait notre code. Avant le premier essai sur clé, le secteur 0 devra commencer par un saut court par-dessus une zone de 0x5A octets laissée libre.
- **Le DHCP** : les valeurs de l'ACK plutôt que de l'offre (ce que demande la RFC 2131 ; Linux garde l'offre), la porteuse pas attendue (Linux l'attend jusqu'à 120 s), pas de renouvellement du bail (celui de slirp dure un jour).

**Si une mesure ou un programme le demande**

- **Grandes allocations.** Un bloc du tas ne dépasse pas 4 Mio (l'ordre maximal du buddy). `vmalloc.rs` projette déjà des pages éparses d'un seul tenant (les piles depuis 6e, `ioremap`) ; ce qui manque, c'est l'allocation générale au-delà de 4 Mio. Pour les mémoires WebAssembly, avec le compilateur (« Plus tard ») : 4 Gio d'adresses suivies de pages de garde (comme wasmtime), ce qui supprimera aussi le contrôle des bornes.
- **La recherche d'un nom dans un dossier** parcourt ses entrées ; une table de hachage (le dcache de Linux) si une mesure le demande.
- **Archive cpio** : archives concaténées et compressées.
- **O_TMPFILE et RENAME_WHITEOUT** : refusés (EOPNOTSUPP, EINVAL) ; le premier pour des fichiers sans nom, le second pour overlayfs.
- **/proc** (6f) : fabriqué à la demande, mais avec seulement ce que demandent nos programmes et `claude` (maps, statm, comm, exe, task, fd) ; ni `stat`, ni `status`, ni `/proc/version`, ni `ns/`, que `claude -p` cherche et dont il se passe. Chercher dans le dossier d'un processus parti rend ENOENT (Linux : ESRCH, par la permission de traverser). **/proc et /sys** (6d) : root ne peut pas changer les droits de la racine de /proc ni d'un nœud de sysfs (Linux le permet).
- **epoll** (6f) : Linux refuse un ajout qui ferait plus de 1000 chemins de réveil vers un même fichier (`reverse_path_check`), pas nous.
- **Le détecteur d'interblocage** épargne un programme bloqué pour toujours dès qu'une de ses sockets est dans un epoll, même que personne n'attend (épargner trop rejoint Linux, qui ne tue jamais personne) : à revoir si la boucle de Bun le montre.
- **ICMP** : la limite des erreurs par destination (`inet_peer`) manque, seule la limite globale est faite. Les options IP ne sont pas validées une à une (`ip_options_compile`) : seules les routes sources sont jetées, sans « problème de paramètre » pour une option fausse.
- **Une diffusion envoyée** n'est pas rendue aussi aux sockets de la machine (Linux en fait une copie par la boucle) ; ni multidiffusion, ni MSG_MORE et UDP_CORK, ni IP_OPTIONS et IP_RECVTTL (ENOPROTOOPT) ; SO_SNDBUF ne fait jamais attendre. L'interface d'IP_PKTINFO à l'envoi n'est que vérifiée (ENODEV), pas prise pour sortie.
- **La glibc vient de la machine hôte** (`glibc/`, refaite d'après une empreinte du contenu) : le résultat dépend de l'Ubuntu de l'hôte. WSL et la CI sont tous deux en 24.04 ; une empreinte attendue, comme pour `claude`, arrêterait une construction faite avec une autre glibc, mais aussi chaque mise à jour de sécurité d'Ubuntu : à faire si les deux divergent un jour.
- **Les tests du démarrage** : `verifier.sh` cherche chaque ligne attendue n'importe où dans le journal, sans en vérifier l'ordre (une ligne peut être satisfaite par un autre programme, plus loin), et quelques morceaux attendus sont très courts (« [noyau] TSC : »). Depuis 6h, il échoue sur tout « ECHEC » ou « PANIQUE » du journal. Vérifier l'ordre, si un test passe un jour à tort.

### Les écarts voulus avec Linux

- **Les programmes** : un interpréteur passe par toutes les vérifications du programme (Linux ne vérifie son genre et ses segments qu'après le point de non-retour, et tue le processus), et un interpréteur qui chevauche le programme est refusé (Linux le pose par-dessus) ; un ET_DYN dont un `p_vaddr` relatif dépasse TASK_SIZE est accepté si l'image posée est permise. Écrits en commentaire.
- **La mémoire** : mprotect sur une plage avec un trou ne change rien (Linux change ce qui précède le trou) ; MAP_FIXED est refusé à une zone du maximum même quand les fusions l'auraient fait tenir ; une zone rendue inscriptible deux fois est recomptée (pas de VM_ACCOUNT). Écrits en commentaire.
- **/proc/<pid>/maps et statm** montrent la mémoire du processus tant qu'il vit, même quand son fil principal a fini (Linux, qui la range dans la tâche du fil principal, les montre alors vides : un effet de son organisation, qu'aucun programme n'attend ; l'imiter serait une ligne de `ProcVue`). Décidé avec David le 1er novembre 2026.
- **Un seul utilisateur** (1000, root pour le noyau), sans groupes supplémentaires ni setuid : `protected_symlinks` et `protected_regular` ne sont pas suivis, ils ne protégeraient de rien.
- **Les filles d'une écoute TCP** restent de petites valeurs dans sa file jusqu'à `accept` (Linux en fait des sockets entières dès la poignée de main finie, la `request_sock` ne vivant que jusque-là) : la socket ne naît que dans l'appel système, où sa mémoire peut manquer sans rien perdre, et un client du dehors ne fait allouer au noyau que la petite valeur, sous la borne de la file. Ce qui concerne une fille établie (poll, un RST, une erreur ICMP) passe par son écoute. Choix de 6h, écrit en tête de `reseau/tcp.rs`.
- **Pas d'espaces de noms réseau** : /proc/net est un dossier fixe (Linux : un lien vers self/net). Pas d'IPv6, ni d'AF_NETLINK : la glibc s'en passe.
- **Le DHCP est dans le noyau**, comme l'`ipconfig.c` de Linux, qui ne sert chez lui qu'à démarrer sur le réseau (d'habitude, c'est un programme qui le fait) : faute de shell avant 6l. Il pourra passer dans un programme ensuite.
- **SIOCINQ d'AF_UNIX** dit ce qui reste à lire. Linux 6.18 tient un compte à part (`inq_len`), qui ne descend qu'à la fin d'un message (6 octets à lire, 1 lu : il dit 6), et qui oublie l'octet urgent sauté : il dit 1 sur une file vide, pour toujours. Pas un comportement sur lequel un programme peut compter.
- **Le ramasse-miettes d'AF_UNIX** numérote de vraies composantes : la forme où le `scc_index` de Linux se trompe (r → a → b → a, a → r) fuit chez lui, pas chez nous.
- **Un message d'AF_UNIX sort de sa file pendant sa copie vers le programme** (chez Linux, le paquet y reste) : une copie peut fauter et dormir, et les octets ne se prêtent pas hors du verrou. Il revient à sa place s'il n'est pas tout lu, et un `poll` qui aurait vu la file vide entre-temps est réveillé.

## 24. Questions ouvertes

- Aucune pour l'instant.

## 25. Prochaine étape

Sous-étape 6i : `claude -p "bonjour"`, la première vraie réponse de Claude, et le verrou du processus qui dort (le `mmap_lock` de Linux). Son plan sera écrit et relu au début de son fil, avec ce que 6h a appris (`etape-06/plan.md` dans les fichiers du projet pour le découpage).
