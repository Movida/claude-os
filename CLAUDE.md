# OS minimal pour Claude Code

Projet d'apprentissage : écrire soi-même, brique par brique, un OS x86 qui démarre sur du vrai matériel comme en VM, et qui fera tourner à terme le vrai Claude Code.

Architecture hybride :

- **WebAssembly est le format natif des programmes de l'OS.** Le noyau embarque un moteur Wasm, et chaque programme tourne dans le bac à sable Wasm (isolation à la façon de Nebulet), avec WASI comme interface système.
- **Une couche de compatibilité Linux minimale** sert uniquement à exécuter le binaire `claude` tel quel : un ELF x86_64 dynamique, qui demande aussi ld-linux et la glibc.
- Le socle natif (démarrage, mémoire, interruptions, pilotes) est en assembleur, puis dans le langage du noyau, encore à choisir.

Le vrai Claude Code plutôt qu'un agent maison, parce que David veut utiliser son abonnement Claude, réservé aux applications officielles. Et il n'existe qu'en binaire natif : d'où la couche Linux à côté de Wasm. Le détail des décisions et les questions ouvertes sont dans `HISTORIQUE.md`.

## Façon de travailler

- Le but est d'apprendre, pas d'aller vite. David apprend en lisant le code et ses commentaires, sans exercices pratiques : Claude écrit tout, y compris les morceaux qui comportent un vrai choix de conception.
- Pour chaque choix de conception, Claude retient l'option qui mène au meilleur noyau à terme (celle des noyaux modernes comme Linux, sauf raison contraire) et explique en commentaire les options écartées et pourquoi. Pas de `TODO(human)`.
- Le code est commenté en français et explique le *pourquoi*, pas seulement le *quoi*.
- Les messages affichés par l'OS n'ont pas d'accents : la police du BIOS utilise la page de code 437, pas l'UTF-8.
- Une étape = un dossier numéroté (`01-boot/`, `02-…/`), chacun avec son propre Makefile.

## Historique git

Le dépôt (github.com/Movida/claude-os) doit se lire étape par étape.

- Un commit = un changement logique. Sujet sans accents : `Etape NN : ...`, `Outillage : ...` ou `Projet : ...`.
- Nouvelle étape : pas de commit de copie. Pour voir ce qu'une étape ajoute à la précédente, comparer les fichiers : `git diff --no-index 01-boot/boot.asm 02-mode-protege/boot.asm`.
- Un choix de conception important fait l'objet d'un commit à part, pour qu'on le retrouve facilement dans l'historique.
- Étape vérifiée dans QEMU : tag `etape-NN` (à pousser depuis la VM de David, le proxy de la session cloud refuse les tags).
- On ne réécrit l'historique que tant que personne d'autre ne l'a récupéré ; ensuite, uniquement de nouveaux commits.

## Outils

- `nasm` et `qemu-system-x86_64` (`sudo apt install nasm qemu-system-x86`).
- Dans chaque étape : `make` pour construire, `make run` pour démarrer dans QEMU, `make dump` pour inspecter l'image.

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
3. Mémoire, interruptions, clavier
4. Interpréteur WebAssembly dans le noyau (d'abord une bibliothèque testée sur l'hôte avec la suite de tests officielle de Wasm), puis WASI minimal (`fd_write`, `proc_exit`)
5. Chargeur ELF et premiers appels système Linux (`write`, `exit`)
6. Processus, système de fichiers, réseau (virtio), TLS… jusqu'à Claude Code

Plus tard : un chargeur UEFI, nécessaire pour démarrer sur les PC récents sans mode Legacy/CSM.
