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

## 10. Questions ouvertes

- Aucune pour l'instant.

## 11. Prochaine étape

Étape 3 : mémoire, interruptions, clavier. Une table d'interruptions (IDT) pour attraper les exceptions du processeur au lieu de redémarrer, l'horloge, puis le clavier. C'est aussi le moment de charger un vrai noyau, écrit en Rust, depuis notre chargeur.
