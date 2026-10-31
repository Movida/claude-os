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
2. **Le lanceur, `/etc/demarrage`** (choix de conception) : sans `fork` ni `execve` (6k), le noyau joue le rôle d'`init` et lance une commande par ligne, avec ses arguments et son environnement. Un sous-ensemble strict de la syntaxe du `sh` de POSIX (dash), vérifié contre le `sh` de la machine : le programme par son chemin absolu, `NOM=valeur` en tête, et une seule entorse, `--dir=` pour les dossiers pré-ouverts d'un programme WebAssembly. Le droit d'exécuter vérifié avant tout, pour tous les formats ; plus de limite de 32 arguments (celles de Linux : la place, 128 Kio par chaîne) ; WASI apprend une table des dossiers pré-ouverts, `args_get` et `environ_get`.
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
- **un défaut latent pour 6k** : un fichier de /proc gardé ouvert après la fin de son processus aurait fait paniquer le noyau, ou désigné en silence le fichier d'un autre processus (les numéros d'inode étaient repris) ; ils ne le sont plus, et un objet disparu répond ENOENT ;
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

## 19. Reste à faire

**Dans le noyau**

- **Allocations faillibles.** Une allocation impossible, hors de `try_reserve`, fait paniquer le noyau. Rust pour Linux n'utilise que des allocations qui rendent une erreur : à généraliser avant que des programmes puissent en abuser.
- **Grandes allocations.** Un bloc du tas ne dépasse pas 4 Mio (l'ordre maximal du buddy) : il faudra projeter des pages éparses d'un seul tenant (`vmalloc`). Pour les mémoires WebAssembly, réserver 4 Gio d'adresses suivies de pages de garde (comme wasmtime), ce qui supprimera aussi le contrôle des bornes une fois le code compilé.
- **Console non bloquante.** Le port série fait attendre activement (87 µs par octet sur du vrai matériel) : un pilote à interruptions et une file d'attente, comme le tty de Linux.
- **Pages globales** (CR4.PGE) pour le noyau, maintenant qu'il y a un espace d'adressage par programme ; KPTI et PCID : en 6m.
- **`iretq` qui fauterait** (un RIP non canonique écrit par le noyau, pour exec ou les signaux) : une entrée de la table d'exceptions qui transforme la faute en signal pour le programme (`bad_iret` de Linux). Inatteignable aujourd'hui : le RIP d'un cadre vient toujours du programme.
- **La carte des zones et la réserve** : la carte d'un programme vient du tas du noyau, qui peut puiser dans la réserve (3 Mio au plus, 5 le temps de l'agrandir) ; Linux prend ses `vm_area_struct` au-dessus du seuil. Avec les allocations faillibles.
- **Le verrou du processus coupe les interruptions** : un munmap ou la fin d'un programme qui a touché des centaines de Mio rend ses cadres d'un trait, et des tics d'horloge se perdent ; il sérialise aussi les fautes de page de tous les fils. Un verrou qui dort, en lecture et écriture (le `mmap_lock` de Linux).
- **MAP_SHARED d'un fichier** reste refusé : il faudra écrire les pages dans le fichier, et les retrouver dans chaque processus qui le projette (la carte inverse `i_mmap`, 6k). Pour la même raison, raccourcir un fichier ne retire ses pages que des projections du processus en cours : un autre programme qui le projette (`&`) y lit l'ancien contenu au lieu d'un SIGBUS.
- **Les verrous de fichiers** (fcntl, flock) sont vérifiés mais toujours accordés : deux programmes lancés par `&` ne s'excluent pas. Une vraie table des verrous.
- **Le tueur OOM** tue le programme qui faute, pas le plus gros : avec plusieurs programmes à la fois, un petit peut payer pour un gros.
- **/proc fabriqué à la demande** : les dossiers des processus et des fils sont des entrées gardées (la place réservée pour tous les fils possibles) ; Linux les fabrique d'après la table des tâches. Avec /proc/<pid>/fd (6f), qui le demandera vraiment : des numéros d'inode qui disent le processus, le fil et l'entrée. Écarts voulus d'ici là : /proc/<tid> d'un fil non principal (ENOENT), maps et statm quand le fil principal a fini.
- **Les fils** : CLOSE_RANGE_UNSHARE refusé avec plusieurs fils (la table est au processus) ; CLONE_PIDFD, set_tid, CLONE_INTO_CGROUP, CLONE_CLEAR_SIGHAND, un processus neuf (fork, vfork : 6k) rendent ENOSYS, un espace de noms EPERM (CLONE_NEWUSER compris, que Linux permet) ; la base de GS n'est pas sauvée par tâche (arch_prctl refuse ARCH_SET_GS) ; RLIMIT_SIGPENDING n'est pas appliquée.
- **Préempter en rendant un verrou** (Linux le fait) : chez nous, un réveil fait dans le noyau ne prend effet qu'au retour vers l'anneau 3 ou au tic suivant.
- **Le test « lignes »** ne peut pas prouver le verrou des écritures de la console sous QEMU sans accélération (TCG ne livre l'horloge qu'entre deux blocs traduits) ; à revoir sur un vrai processeur ou avec le multiprocesseur.
- **WebAssembly** : l'O_TRUNC de path_open se fait sans le verrou d'écriture de l'inode.
- **Les limites de ressources** autres que celle des descripteurs sont gardées et rendues, pas appliquées (la pile reste à 8 Mio quoi qu'on demande).
- **Un seul utilisateur** (1000, root pour le noyau), sans groupes supplémentaires ni setuid : `protected_symlinks` et `protected_regular` ne sont pas suivis, ils ne protégeraient de rien.
- **O_TMPFILE et RENAME_WHITEOUT** : refusés (EOPNOTSUPP, EINVAL) ; le premier pour des fichiers sans nom, le second pour overlayfs.
- **La recherche d'un nom dans un dossier** parcourt ses entrées ; une table de hachage (le dcache de Linux) si une mesure le demande.
- **Écarts voulus avec Linux**, écrits en commentaire : un interpréteur passe par toutes les vérifications du programme (Linux ne vérifie son genre et ses segments qu'après le point de non-retour, et tue le processus), et un interpréteur qui chevauche le programme est refusé (Linux le pose par-dessus) ; un ET_DYN dont un `p_vaddr` relatif dépasse TASK_SIZE est accepté si l'image posée est permise ; mprotect sur une plage avec un trou ne change rien (Linux change ce qui précède le trou) ; MAP_FIXED est refusé à une zone du maximum même quand les fusions l'auraient fait tenir ; une zone rendue inscriptible deux fois est recomptée (pas de VM_ACCOUNT).
- **Archive cpio** : archives concaténées et compressées.
- **La console écrit au plus 1024 octets par appel**, et ld-linux ne reprend pas une écriture courte (`ld.so --help` est coupé ; stdio et Bun reprennent). Linux n'écrit jamais court sur un terminal, mais il peut attendre et être interrompu ; notre port série fait attendre activement : le terminal à interruptions et sa file (6j).
- **Le lanceur `/etc/demarrage`** cède la place à un vrai `/init` et à un shell avec `fork` et `execve` (6k) ; son dossier courant est `/`, que l'utilisateur 1000 ne peut pas écrire (à revoir pour `claude`, 6i). Une limite de temps : le programme la pose (setrlimit), et le shell aura `ulimit -t` (6k).
- **Le vecteur auxiliaire** n'a pas AT_SYSINFO_EHDR (le vDSO, 6m), AT_MINSIGSTKSZ (6f), AT_RSEQ_* ; `rseq` rend ENOSYS : la glibc a un repli pour chacun.
- **Tas :** des listes par processeur pour le multiprocesseur.
- **Les signaux** (6d) sont enregistrés, pas encore livrés à un gestionnaire (le cadre de signal, `rt_sigreturn`, SA_RESTART : 6f) ; les signaux temps réel n'ont pas encore de file ; le pid 1 n'a pas le statut à part de Linux. Une attente que rien ne finira (plus aucune tâche prête ni minuterie) arrête les programmes qui dorment, par SIGKILL et en le disant, faute de terminal pour les interrompre ; `epoll_wait` rend ENOSYS (6f).
- **/proc et /sys** (6d) : root ne peut pas changer les droits de la racine de /proc ni d'un nœud de sysfs (Linux le permet) ; un numéro d'inode de /proc n'est jamais repris, ENOSPC après quatre milliards d'entrées.
- **`mknodat`** (259) est encore un appel inconnu (avec le shell, 6k).

**Pour le vrai matériel**

- **L'APIC n'est vérifié que sous QEMU**, en xAPIC ; x2APIC (que TCG n'imite pas) fait revenir au 8259. Non vérifiés faute de pouvoir les imiter : `sysretq` avec un SS nul après une bascule sur AMD (le `X86_BUG_SYSRET_SS_ATTRS` de Linux), une adresse ACPI au-delà de MAXPHYADDR (Linux la refuse).

- **NMI pendant le passage éclair en mode protégé du chargeur** : non masqué (Linux le masque par le port 0x70 pour son passage définitif). Risque infime, à revoir si un essai sur vrai matériel le montre.
- **Démarrage sur clé USB : réserver un BPB factice dans le secteur 0.** Pour une clé, certains BIOS « émulent » une disquette et croient trouver au début du secteur 0 un BPB (BIOS Parameter Block, la description d'un système de fichiers FAT) : ils réécrivent les octets 3 à 0x5A avec leurs propres valeurs, ce qui écraserait notre code. Avant le premier essai sur clé, le secteur 0 devra commencer par un saut court par-dessus une zone de 0x5A octets laissée libre.

## 20. Questions ouvertes

- Aucune pour l'instant.

## 21. Prochaine étape

Sous-étape 6f : les signaux livrés à leurs gestionnaires (le cadre de signal, `rt_sigreturn`, SA_RESTART), `epoll_wait` qui attend vraiment, `eventfd`, les tubes. Son plan sera écrit et relu au début de son fil, avec ce que 6e a appris (`etape-06/plan.md` dans les fichiers du projet pour le découpage).
