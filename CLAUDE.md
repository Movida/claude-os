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
- Une étape = un dossier numéroté (`01-boot/`, `02-…/`), chacun avec son propre Makefile. Une sous-étape porte sa lettre (`06a-memoire/`, `06b-…/`), avec son tag (`etape-06a`) et son propre fil de discussion.

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
- Depuis l'étape 4 : `make tests-hote` télécharge la suite de tests officielle de WebAssembly et `wast2json` (wabt 1.0.39, binaire officiel pour Linux x86_64), qui la convertit, à des versions figées vérifiées par SHA-256.
- Étape 5 : `gcc`, `libc6-dev` (la glibc statique, pour `gcc -static`) et `strace` (installés par le Dockerfile). Les programmes Linux de test (`05-elf/linux/`) tournent aussi tels quels sur la machine hôte. `make trace` montre les appels système d'un programme C dans notre noyau, à côté de `strace` sur l'hôte.
- Depuis 6a : `make tests-hote` lance aussi `linux/memoire` et `linux/claude-version` sur l'hôte : nos appels de la mémoire (mmap, munmap, mprotect, madvise) doivent s'y comporter comme sous le vrai Linux. Depuis 6b, de même `linux/temps`, `linux/fichiers` et `linux/segments` ; depuis 6c, `linux/dynamique` (avec `LD_LIBRARY_PATH` pour sa bibliothèque de test).
- Depuis 6c : `make` copie dans `glibc/` la glibc partagée de la machine (ld-linux, `libc.so.6` et les quatre autres bibliothèques de `claude`), jamais commitée, et fabrique son `/etc/ld.so.cache` par `/sbin/ldconfig -r` (paquet `libc-bin`, sans root) ; la copie est refaite quand le contenu des fichiers change (une empreinte), pas leur date. Ce que lance le noyau au démarrage, dans l'ordre, avec ses arguments : `racine/etc/demarrage` de l'étape (un sous-ensemble strict de la syntaxe de `sh`, voir `formats/src/commande.rs`).
- Depuis 6d : `make` télécharge le vrai `claude` (2.1.310, paquet npm officiel, empreinte SHA-256 vérifiée) dans `~/.cache/claude-os`, jamais commité ni publié (accord écrit de David pour le télécharger et l'exécuter, ici et dans la CI). La machine de l'étape (disque virtio, `-cpu Nehalem`, `-m 2G`) : `verifier.sh` la demande par `make qemu-disque` et `make qemu-options`. `make tests-hote` lance aussi `linux/signaux`, `systeme`, `evenements` et `proc`. Jamais de trace `strace` de `claude` gardée ou montrée (elle pourrait contenir un jeton) : `make trace` n'en garde que les noms des appels.
- Depuis 6e : `make tests-hote` lance aussi `linux/clone`, `fils` (dont `fils groupe`, qui doit sortir avec 7) et `courses` ; `make tests-qemu` demande `nc` (paquet `netcat-openbsd`, dans le Dockerfile et la CI), pour envoyer une touche au moniteur de QEMU, et échoue sur tout « ECHEC » de son journal.
- Un test qui peut s'emballer se lance avec `ulimit -v` et `timeout` : en 6b, une boucle infinie a rempli toute la mémoire de WSL (le conteneur est depuis plafonné à 8 Go).
- Rust, via `rustup` (installé par le devcontainer). La version exacte est figée dans `03-noyau-rust/noyau/rust-toolchain.toml` ; `rustup` l'installe à la première commande `cargo`.
- Dans chaque étape : `make` pour construire, `make run` pour démarrer dans QEMU, `make dump` pour inspecter l'image ; `make tests-hote` pour les tests qui tournent sur la machine hôte, et `make tests-qemu` pour les scénarios dans QEMU (pannes provoquées, programmes fautifs), quand l'étape en a.

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
4. Interpréteur WebAssembly dans le noyau (d'abord une bibliothèque testée sur l'hôte avec la suite de tests officielle de Wasm), puis WASI minimal (`fd_write`, `proc_exit`) (fait)
5. Chargeur ELF et premiers appels système Linux : un programme C compilé par `gcc -static` tourne dans l'anneau 3 (fait)
6. Jusqu'à Claude Code, en treize sous-étapes (le découpage et le plan de chacune : `etape-06/plan.md` dans les fichiers du projet) :
   - 6a. Mémoire virtuelle à la demande : zones, fautes de page servies, page de zéros, pile qui grandit, surengagement et OOM, mmap/munmap/mprotect/madvise anonymes (fait)
   - 6b. Système de fichiers en mémoire, descripteurs, cache des pages, mmap de fichiers (fait)
   - 6c. Programmes dynamiques : ET_DYN, PT_INTERP, ld-linux et la glibc partagée, un lanceur (`/etc/demarrage`) (fait)
   - 6d. `claude --version` (fait)
   - 6e. Ordonnanceur, APIC et IO-APIC, fils (`clone3`, `futex`) (fait)
   - 6f. Signaux, `epoll`, `eventfd`, tubes
   - 6g. PCI, virtio-net, Ethernet, IPv4, UDP, DNS
   - 6h. TCP, sockets, générateur aléatoire (ChaCha20)
   - 6i. `claude -p "bonjour"` : la première réponse de Claude
   - 6j. Le port série devient un vrai terminal (termios, `/dev/tty`)
   - 6k. `fork`, `execve`, un shell : l'outil Bash de Claude Code
   - 6l. virtio-blk et un système de fichiers persistant
   - 6m. Durcissement : KPTI, PCID, pages globales, ASLR, vDSO

Plus tard : un chargeur UEFI, nécessaire pour démarrer sur les PC récents sans mode Legacy/CSM.
