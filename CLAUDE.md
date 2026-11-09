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
- Au plus bas niveau : aucune crate Rust qui fait le travail à notre place (pas de `bootloader`, `x86_64`, `pic8259`, `uart_16550`…). Le noyau n'utilise que `core` et `alloc` (les collections de Rust : `Vec`, `Box`, `String`…), avec notre propre allocateur ; tout accès au matériel passe par notre code. `unsafe` est cantonné aux modules d'abstraction de bas niveau (le matériel, la mémoire physique, les copies vers les programmes, la synchronisation, la bascule de contexte : leur liste est dans `noyau/src/main.rs`, et `#![deny(unsafe_code)]` le refuse ailleurs) ; chaque bloc dit pourquoi il est sûr (un commentaire `SAFETY:`). Les bibliothèques et la logique des appels système n'en ont pas. Aucune allocation qui panique : le noyau passe par `faillible.rs` et notre `Arc`.
- Les messages affichés par l'OS n'ont pas d'accents : la police du BIOS utilise la page de code 437, pas l'UTF-8.
- Une étape = un dossier numéroté (`01-boot/`, `02-…/`), chacun avec son propre Makefile. Une sous-étape porte sa lettre (`06a-memoire/`, `06b-…/`), avec son tag (`etape-06a`) et son propre fil de discussion. (L'étape 2, antérieure à cette règle : `02-mode-protege/` et `02-mode-long/`, tags `etape-02a` et `etape-02b`.)

## Historique git

Le dépôt (github.com/Movida/claude-os) doit se lire étape par étape.

- Un commit = un changement logique. Sujet sans accents : `Etape NN : ...`, `Outillage : ...` ou `Projet : ...`.
- Nouvelle étape : pas de commit de copie. Pour voir ce qu'une étape ajoute à la précédente, comparer les fichiers : `git diff --no-index 01-boot/boot.asm 02-mode-protege/boot.asm`. Une correction tardive ne touche que l'étape courante : les dossiers des étapes passées gardent ce qu'ils étaient. Seule exception : ce qui empêche `verifier.sh` de passer sur la machine de la CI, où il repasse toutes les étapes (6h : l'adresse d'un BAR sous QEMU 8.2.10 ; les tests sur l'hôte, face à Linux 7.0 et à cinq niveaux de tables ; 6i : `linux/proprietaire` de 6h, qui comptait des SIGIO fondus en un).
- Un choix de conception important est écrit dans le message du commit qui l'implémente (« Choix de conception »), à côté de son code : `git log --grep='hoix de conception'` les retrouve. (La règle de départ voulait un commit à part ; depuis l'étape 4, le choix vit avec son code, ce qui se relit mieux.)
- Avant le premier push d'une étape : relecture de fond, et chaque correction repliée dans le commit qui avait introduit le défaut. La marche à suivre est dans le skill `fin-d-etape` (`.claude/skills/fin-d-etape/`).
- Étape vérifiée dans QEMU : tag `etape-NN` (à pousser depuis la VM de David, le proxy de la session cloud refuse les tags).
- On ne réécrit l'historique que tant que personne d'autre ne l'a récupéré ; ensuite, uniquement de nouveaux commits.

## Outils

- `nasm` (`sudo apt install nasm`) et `qemu-system-x86_64`. Depuis 6h, QEMU 8.2.10 compilé par `.devcontainer/construire-qemu.sh` (dans le Dockerfile et la CI), pas le paquet d'Ubuntu 24.04 : sa version 8.2.2 n'invalide pas un bloc traduit quand on écrit dans sa deuxième page, ce qui fait planter `claude` (`linux/autocode.c` le détecte, `HISTORIQUE.md`, 6h).
- Depuis l'étape 4 : `make tests-hote` télécharge la suite de tests officielle de WebAssembly et `wast2json` (wabt 1.0.39, binaire officiel pour Linux x86_64), qui la convertit, à des versions figées vérifiées par SHA-256.
- Étape 5 : `gcc`, `libc6-dev` (la glibc statique, pour `gcc -static`) et `strace` (installés par le Dockerfile). Les programmes Linux de test (`05-elf/linux/`) tournent aussi tels quels sur la machine hôte. `make trace` montre les appels système d'un programme C dans notre noyau, à côté de `strace` sur l'hôte.
- Depuis 6a : `make tests-hote` lance aussi `linux/memoire` et `linux/claude-version` sur l'hôte : nos appels de la mémoire (mmap, munmap, mprotect, madvise) doivent s'y comporter comme sous le vrai Linux. Depuis 6b, de même `linux/temps`, `linux/fichiers` et `linux/segments` ; depuis 6c, `linux/dynamique` (avec `LD_LIBRARY_PATH` pour sa bibliothèque de test).
- Depuis 6c : `make` copie dans `glibc/` la glibc partagée de la machine (ld-linux, `libc.so.6` et les quatre autres bibliothèques de `claude`), jamais commitée, et fabrique son `/etc/ld.so.cache` par `/sbin/ldconfig -r` (paquet `libc-bin`, sans root) ; la copie est refaite quand le contenu des fichiers change (une empreinte), pas leur date. Ce que lance le noyau au démarrage, dans l'ordre, avec ses arguments : `racine/etc/demarrage` de l'étape (un sous-ensemble strict de la syntaxe de `sh`, voir `formats/src/commande.rs`).
- Depuis 6d : `make` télécharge le vrai `claude` (2.1.310, paquet npm officiel, empreinte SHA-256 vérifiée) dans `~/.cache/claude-os`, jamais commité ni publié (accord écrit de David pour le télécharger et l'exécuter, ici et dans la CI). La machine de l'étape (disque virtio, `-cpu Nehalem`, `-m 2G`) : `verifier.sh` la demande par `make qemu-disque` et `make qemu-options`. `make tests-hote` lance aussi `linux/signaux`, `systeme`, `evenements` et `proc`. Jamais de trace `strace` de `claude` gardée ou montrée (elle pourrait contenir un jeton) : `make trace` n'en garde que les noms des appels.
- Depuis 6e : `make tests-hote` lance aussi `linux/clone`, `fils` (dont `fils groupe`, qui doit sortir avec 7) et `courses` ; `make tests-qemu` demande `nc` (paquet `netcat-openbsd`, dans le Dockerfile et la CI), pour envoyer une touche au moniteur de QEMU, et échoue sur tout « ECHEC » de son journal.
- Depuis 6f : `make tests-hote` lance aussi `linux/gestionnaires`, `reprise`, `suspendre`, `attente` et `tubes` (dont `tubes sigpipe`, qui doit mourir de SIGPIPE : code 141). `make claude-p` lance `claude -p bonjour` (fausse clé, sans réseau) dans une image à part, jusqu'à 240 s sous QEMU, qui doit aller jusqu'à l'appel de l'API (`claude-p-attendu.txt`) ; `make tests-qemu` le lance aussi.
- Depuis 6g : chaque machine de l'étape a sa carte, virtio-net sur le réseau « utilisateur » de QEMU (slirp), par `-netdev user` et `-device virtio-net-pci` (la forme courte `-nic` donne une carte sans MSI-X ; sans option de réseau, QEMU ajoute une e1000) : `make qemu-options` la donne à `verifier.sh`. `make tests-hote` lance aussi `linux/reseau` (les sockets UDP et ICMP, sur lo) et `linux/dns` (un serveur DNS dans le programme). Dans notre noyau, `passerelle` et `make claude-p` demandent `api.anthropic.com` au DNS de slirp, qui relaie celui de l'hôte : il y faut Internet ; `claude -p` va jusqu'à la connexion refusée (pas de TCP avant 6h).
- Depuis 6h : `make` lance d'abord `cargo clippy` (le composant est dans `rust-toolchain.toml`), qui fait respecter les règles du noyau (`noyau/Cargo.toml`, `[lints]`, et `noyau/clippy.toml`) : aucune allocation qui panique, un commentaire `SAFETY:` avant chaque bloc `unsafe`. Pas l'ensemble par défaut de clippy, des conseils de style. Chaque machine de l'étape a aussi un générateur virtio-rng (`-device virtio-rng-pci`, dans `make qemu-options`). `make tests-hote` lance aussi `linux/aleatoire`, `tcp`, `unix`, `proprietaire` (F_SETOWN, SIGURG, O_ASYNC) et `autocode` (du code qui se modifie à cheval sur deux pages, ce que QEMU 8.2.2 ne tient pas), et les tests de `inet` (dont le simulateur de TCP : 200 essais, `SIMULATEUR_ESSAIS` pour plus ; `tests/reception_au_hasard.rs` : `RECEPTION_ESSAIS`), de `crypto` et de `roue` (la roue des minuteurs) ; `make tests-hote-root`, avec sudo, ce que `linux/pmtu` demande (une socket brute, dans l'espace réseau de la machine). Le noyau affiche à chaque fin d'étape de démarrage ce que ses piles ont pris (« Piles du noyau : N octets au plus ») : ECHEC au-delà des trois quarts. Les outils `cargo mutants` et le fuzz restent hors du dépôt. La page HTTP de test vient d'`outils/serveur-http` (`sh` et `awk`), que QEMU lance pour chaque connexion vers 10.0.2.100:80 (`guestfwd=...-cmd:`), sans port ouvert sur l'hôte ; `claude -p` va jusqu'à l'API, qui répond « Invalid API key » à la fausse clé.
- Depuis 6i : `make tests-hote` lance aussi `linux/fautes`, `troncature`, `redirections`, `dossier` (la même suite de `cd` jouée par dash, sans environnement), `effacer`, `copies` et `surveillance` (ces deux-là et `troncature` dans /dev/shm, un tmpfs comme notre /tmp). `make verrous` : le démarrage avec les statistiques des verrous (pour chaque endroit, le temps le plus long interruptions coupées : le `lock_stat` de Linux). `make claude-p` parle aussi à une fausse API que sert `outils/serveur-http` (`outils/fausse-api.sse`), sans jeton ni Internet : sa réponse, le code 0, et le groupe de `/etc/demarrage-claude-p` qui rend toute sa mémoire. `make claude-bonjour` : la vraie réponse de Claude, avec l'abonnement de David, par le jeton de `claude setup-token` que `make jeton` (dans un terminal du conteneur) range dans `~/.config/claude-os/jeton` (0600 ; ni dans le dépôt, ni dans `~/.claude`, ni dans la CI ; à refaire après une reconstruction du conteneur). Ce fichier, Claude ne le lit jamais, ne l'affiche pas, ne le passe ni dans une commande ni dans une variable ; les réglages de Claude Code du conteneur (`~/.claude/settings.json`, `permissions.deny`, voulus par David) refusent aux sessions de lire ou d'écrire `~/.config/claude-os/`, et toute commande Bash qui nomme ce dossier. Seul `make claude-bonjour` s'en sert (il dit lui-même si le jeton manque), par une image privée (`~/.config/claude-os/image`, effacée à la fin), sans la mémoire de QEMU dans un fichier core (`-machine dump-guest-core=off`). Le lancer demande l'accord de David (une requête à l'API par essai).
- Depuis 6j : chaque machine de l'étape a quatre processeurs (`-smp 4`, dans `make qemu-options`), et `make tests-qemu` garde un scénario à un seul (`-smp 1`), un pour le TSC (`test-tsc`, `-cpu Nehalem`), un secondaire qui tarde et qu'on abandonne (`test-retard`) et le NMI du moniteur pendant que `processeurs boucle` tourne (`nmi.bin`). `DUREE` vaut 120 s (le double des 54 s mesurées : les tests du multiprocesseur au démarrage). `make tests-hote` lance aussi `linux/processeurs` (l'affinité, `getcpu`, des fils épinglés) ; `fautes` vérifie le vidage des TLB entre processeurs (« TLB perimee ») et les fautes servies pendant un `munmap` (« munmap en lecture »). `make verrous` montre aussi les seize endroits les plus attendus par un autre processeur (la contention, comptée à chaque prise) et les verrous qui dorment pris en tournant ou en dormant ; `make verrous-claude-p` les mesure pendant `claude -p` (c'est ce qui a décidé de garder un seul verrou pour le tas et le générateur). `make trace` ne trace plus que `claude --version` (`racine/etc/demarrage-trace`), une ligne par appel, et s'arrête à sa fin. Le démarrage nomme la tâche dont la pile est descendue le plus bas (« Piles du noyau »). Le conteneur a douze cœurs : deux QEMU à quatre processeurs à la fois restent la limite, et rien ne se construit pendant qu'une vérification tourne (elles partagent `programmes.cpio` et les dossiers de compilation).
- Un test qui peut s'emballer se lance avec `ulimit -v` et `timeout` : en 6b, une boucle infinie a rempli toute la mémoire de WSL (le conteneur est depuis plafonné à 8 Go).
- Remote Control : le processus principal du conteneur est un superviseur (`.devcontainer/remote-control.sh`, copié dans l'image), qui lance `claude remote-control` et le relance s'il s'arrête ; journal : `~/.claude/remote-control.log`. Le modifier demande de reconstruire le conteneur. Mode d'emploi et réglages côté Windows : `.devcontainer/README.md` ; tests avec un faux serveur : `.devcontainer/test-remote-control.sh`.
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
6. Jusqu'à Claude Code, en quatorze sous-étapes (le découpage et le plan de chacune : `etape-06/plan.md` dans les fichiers du projet ; le multiprocesseur, 6j, ajouté par la relecture globale du 2 novembre 2026, qui a décalé les lettres suivantes, voir `HISTORIQUE.md`) :
   - 6a. Mémoire virtuelle à la demande : zones, fautes de page servies, page de zéros, pile qui grandit, surengagement et OOM, mmap/munmap/mprotect/madvise anonymes (fait)
   - 6b. Système de fichiers en mémoire, descripteurs, cache des pages, mmap de fichiers (fait)
   - 6c. Programmes dynamiques : ET_DYN, PT_INTERP, ld-linux et la glibc partagée, un lanceur (`/etc/demarrage`) (fait)
   - 6d. `claude --version` (fait)
   - 6e. Ordonnanceur, APIC et IO-APIC, fils (`clone3`, `futex`) (fait)
   - 6f. Signaux, `epoll`, `eventfd`, tubes (fait)
   - 6g. PCI, virtio-net, Ethernet, IPv4, UDP, DNS (fait)
   - 6h. TCP, sockets, générateur aléatoire (ChaCha20) (fait)
   - 6i. `claude -p "bonjour"` : la première réponse de Claude ; le verrou du processus devient un verrou qui dort (le `mmap_lock` de Linux) (fait)
   - 6j. Le multiprocesseur : les processeurs secondaires (INIT-SIPI-SIPI), une zone par processeur et `swapgs`, des verrous qui attendent vraiment, le vidage des TLB par IPI, une file des prêtes par processeur, les verrous qui dorment qui tournent d'abord sur leur détenteur, `munmap` en lecture, la contention mesurée pendant `claude -p` (fait)
   - 6k. Le port série devient un vrai terminal (termios, `/dev/tty`)
   - 6l. `fork`, `execve`, un shell : l'outil Bash de Claude Code
   - 6m. virtio-blk et un système de fichiers persistant (avec une couche VFS : des opérations par système de fichiers, que demandera ext2)
   - 6n. Durcissement : KPTI, PCID, pages globales, ASLR, vDSO

Plus tard :

- un chargeur UEFI, nécessaire pour démarrer sur les PC récents sans mode Legacy/CSM ;
- un compilateur WebAssembly vers x86_64 dans le noyau (du code compilé en anneau 0, isolé par des pages de garde : ce qui fait la force de Nebulet), puis les flottants du processeur, dans une section « FPU du noyau » (le `kernel_fpu_begin` de Linux), à la place des flottants en arithmétique entière de l'interpréteur ;
- les pilotes du vrai matériel : un disque (AHCI ou NVMe), une carte réseau (e1000e ou Realtek), le clavier USB (xHCI), PCI Express par ECAM et l'AML de l'ACPI, et le BPB factice pour démarrer sur une clé USB.
