# OS minimal pour Claude Code

Projet d'apprentissage : écrire soi-même, brique par brique, un OS x86 qui démarre sur du vrai matériel comme en VM, et qui fera tourner à terme le vrai Claude Code.

Architecture hybride :

- **WebAssembly est le format natif des programmes de l'OS.** Le noyau embarque un moteur Wasm, et chaque programme tourne dans le bac à sable Wasm (isolation à la façon de Nebulet), avec WASI comme interface système.
- **Une couche de compatibilité Linux minimale** sert uniquement à exécuter le binaire `claude` tel quel : un ELF x86_64 dynamique, qui demande aussi ld-linux et la glibc.
- Le socle natif est écrit en assembleur pour le démarrage (notre propre chargeur), puis en **Rust** pour le noyau (mémoire, interruptions, pilotes).

Le vrai Claude Code plutôt qu'un agent maison, parce que David veut utiliser son abonnement Claude, réservé aux applications officielles. Et il n'existe qu'en binaire natif : d'où la couche Linux à côté de Wasm. Le détail des décisions et les questions ouvertes sont dans `HISTORIQUE.md`.

## Façon de travailler

- Le but est d'apprendre, pas d'aller vite. David apprend en lisant le code et ses commentaires, sans exercices pratiques : Claude écrit tout, y compris les morceaux qui comportent un vrai choix de conception.
- Pour chaque choix de conception, Claude retient l'option qui mène au meilleur noyau à terme (celle des noyaux modernes comme Linux, sauf raison contraire) et explique en commentaire les options écartées et pourquoi. Pas de `TODO(human)`.
- Le code est commenté en français et explique le *pourquoi*, pas seulement le *quoi*.
- Au plus bas niveau : aucune crate Rust qui fait le travail à notre place (pas de `bootloader`, `x86_64`, `pic8259`, `uart_16550`…). Le noyau n'utilise que `core` et `alloc` (les collections de Rust : `Vec`, `Box`, `String`…), avec notre propre allocateur ; tout accès au matériel passe par notre code, avec `unsafe` cantonné aux quelques fonctions qui touchent le matériel.
- Les messages affichés par l'OS n'ont pas d'accents : la police du BIOS utilise la page de code 437, pas l'UTF-8.
- Une étape = un dossier numéroté (`01-boot/`, `02-…/`), chacun avec son propre Makefile.

## Historique git

Le dépôt (github.com/Movida/claude-os) doit se lire étape par étape.

- Un commit = un changement logique. Sujet sans accents : `Etape NN : ...`, `Outillage : ...` ou `Projet : ...`.
- Nouvelle étape : pas de commit de copie. Pour voir ce qu'une étape ajoute à la précédente, comparer les fichiers : `git diff --no-index 01-boot/boot.asm 02-mode-protege/boot.asm`.
- Un choix de conception important fait l'objet d'un commit à part, pour qu'on le retrouve facilement dans l'historique.
- Avant le premier push d'une étape : relecture de fond, et chaque correction repliée dans le commit qui avait introduit le défaut. La marche à suivre est dans le skill `fin-d-etape` (`.claude/skills/fin-d-etape/`).
- Étape vérifiée dans QEMU : tag `etape-NN` (à pousser depuis la VM de David, le proxy de la session cloud refuse les tags).
- On ne réécrit l'historique que tant que personne d'autre ne l'a récupéré ; ensuite, uniquement de nouveaux commits.

## Outils

- `nasm` et `qemu-system-x86_64` (`sudo apt install nasm qemu-system-x86`).
- Étape 4 : `make tests-hote` télécharge la suite de tests officielle de WebAssembly et `wast2json` (wabt 1.0.39, binaire officiel pour Linux x86_64), qui la convertit, à des versions figées vérifiées par SHA-256.
- Rust, via `rustup` (installé par le devcontainer). La version exacte est figée dans `03-noyau-rust/noyau/rust-toolchain.toml` ; `rustup` l'installe à la première commande `cargo`.
- Dans chaque étape : `make` pour construire, `make run` pour démarrer dans QEMU, `make dump` pour inspecter l'image ; `make tests-hote` pour les tests qui tournent sur la machine hôte, quand l'étape en a.

## Tester sans écran

Tout ce que l'OS affiche part aussi sur le port série COM1 (port 0x3F8). Pour vérifier une étape :

```sh
qemu-system-x86_64 -drive format=raw,file=boot.bin -display none \
  -serial file:serial.log -monitor unix:mon.sock,server,nowait
```

Puis lire `serial.log`. Pour une capture de l'écran, envoyer `screendump ecran.ppm` sur la socket du moniteur QEMU.

## Feuille de route

1. Secteur de démarrage 16 bits, démarrage BIOS legacy (fait)
2. Passage en mode protégé 32 bits, puis en mode long 64 bits (fait)
3. Noyau Rust : interruptions, horloge, clavier, mémoire physique (fait)
4. Interpréteur WebAssembly dans le noyau (d'abord une bibliothèque testée sur l'hôte avec la suite de tests officielle de Wasm), puis WASI minimal (`fd_write`, `proc_exit`)
5. Chargeur ELF et premiers appels système Linux (`write`, `exit`)
6. Processus, système de fichiers, réseau (virtio), TLS… jusqu'à Claude Code

Plus tard : un chargeur UEFI, nécessaire pour démarrer sur les PC récents sans mode Legacy/CSM.
