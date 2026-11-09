# claude-os

[![QEMU](https://github.com/Movida/claude-os/actions/workflows/qemu.yml/badge.svg)](https://github.com/Movida/claude-os/actions/workflows/qemu.yml)

Un OS x86 écrit de zéro, brique par brique, pour apprendre comment tout fonctionne au plus bas niveau. Son but à terme : faire tourner le vrai Claude Code.

> *A from-scratch x86 operating system, built step by step as a learning project: NASM boot sector, `no_std` Rust kernel, a WebAssembly/WASI runtime as the native program format, and a minimal Linux compatibility layer whose goal is to run the real, unmodified `claude` binary. Code and comments are in French.*

## Où en est le projet

Claude répond : le binaire officiel de Claude Code, un ELF x86_64 dynamique chargé avec ld-linux et la glibc de la machine, sans aucune modification, répond à `claude -p bonjour` dans notre noyau, avec l'abonnement de David. Il passe par notre pile TCP/IP, y fait son TLS, surveille ses réglages par inotify et copie ses fichiers par `copy_file_range`. `claude --version` y tourne depuis 6d. Depuis 6j, le noyau tourne sur quatre processeurs (une zone par processeur et `swapgs`, des verrous qui attendent vraiment, le vidage des TLB par IPI, une file des prêtes par processeur), et `claude -p` y répond en 18 s sous QEMU. La prochaine étape : le terminal (6k).

```
[16 bits] Noyau lu sur le disque, recopie a 1 Mio en mode irreel.
[64 bits] Mode long actif !
[noyau] Bonjour depuis le noyau Rust !
...
```

## Architecture

- **Démarrage** : notre propre chargeur en assembleur (BIOS legacy), passage du mode réel 16 bits au mode protégé 32 bits puis au mode long 64 bits.
- **Noyau Rust** `no_std` : interruptions, APIC, pagination W^X, allocateur buddy, mémoire virtuelle à la demande, système de fichiers en mémoire, ordonnanceur EEVDF et fils, verrous qui dorment, signaux, `epoll`, tubes, inotify, pile réseau (PCI, virtio-net, IPv4, UDP, TCP, DNS, AF_UNIX), générateur aléatoire de Linux (ChaCha20). Aucune crate qui fait le travail à notre place : seulement `core` et `alloc`, avec notre propre allocateur. `unsafe` est réservé aux modules d'abstraction de bas niveau, et aucune allocation du noyau ne panique : le compilateur et `cargo clippy` le vérifient.
- **WebAssembly est le format natif des programmes** : le noyau embarque un interpréteur Wasm, testé contre la suite officielle de WebAssembly, avec WASI comme interface système, sockets comprises (isolation à la façon de Nebulet).
- **Une couche de compatibilité Linux minimale**, uniquement pour exécuter `claude` tel quel : chargeur ELF, anneau 3, appels système de Linux, programmes dynamiques.

## Les étapes

Chaque étape est un dossier autonome avec son propre `Makefile`, et un tag `etape-NN` quand elle est vérifiée dans QEMU. Pour voir ce qu'une étape ajoute à la précédente : `git diff --no-index 01-boot/boot.asm 02-mode-protege/boot.asm`.

| Dossier | Ce qu'il apporte |
|---|---|
| `01-boot/` | Secteur de démarrage 16 bits |
| `02-mode-protege/`, `02-mode-long/` | Mode protégé 32 bits, puis mode long 64 bits |
| `03-noyau-rust/` | Noyau Rust : interruptions, horloge, clavier, mémoire physique |
| `04-wasm/` | Interpréteur WebAssembly et WASI minimal |
| `05-elf/` | Chargeur ELF : un programme C `gcc -static` dans l'anneau 3 |
| `06a-memoire/` | Mémoire virtuelle à la demande, `mmap` et compagnie |
| `06b-fichiers/` | Système de fichiers en mémoire, descripteurs, cache des pages |
| `06c-dynamique/` | Programmes dynamiques : ld-linux et la glibc partagée |
| `06d-claude-version/` | `claude --version` |
| `06e-ordonnanceur/` | Ordonnanceur EEVDF, APIC et IO-APIC, fils (`clone3`, `futex`) |
| `06f-signaux/` | Signaux, `epoll`, `eventfd`, tubes, `/proc` à la demande |
| `06g-reseau/` | PCI, virtio-net, Ethernet, IPv4, UDP, ICMP, DNS |
| `06h-tcp/` | Le générateur aléatoire de Linux, TCP, AF_UNIX, les sockets de WASI |
| `06i-claude-p/` | La première réponse de Claude : la mémoire sous un verrou qui dort, `sendfile` et `copy_file_range`, inotify |
| `06j-multiprocesseur/` | Le multiprocesseur : les processeurs secondaires, `swapgs`, des verrous qui attendent vraiment, le vidage des TLB, une file des prêtes par processeur |

La feuille de route complète (le terminal, le shell, le disque…) est dans [`CLAUDE.md`](CLAUDE.md), et le récit des décisions dans [`HISTORIQUE.md`](HISTORIQUE.md).

## Essayer

Outils : `nasm`, `qemu-system-x86_64` (8.2.3 ou plus : `.devcontainer/construire-qemu.sh`, le paquet d'Ubuntu 24.04 a un bogue qui fait planter `claude`), `gcc`, `libc6-dev`, et Rust via `rustup` (la version est figée dans `rust-toolchain.toml`). Le plus simple est d'ouvrir le dépôt dans son devcontainer (`.devcontainer/`), qui installe tout.

```sh
cd 03-noyau-rust
make          # construit l'image
make run      # démarre dans QEMU
```

Pour vérifier toutes les étapes d'un coup, comme la CI : `./verifier.sh`.

L'étape 6d télécharge le binaire officiel de Claude Code (paquet npm, empreinte SHA-256 vérifiée) dans `~/.cache/claude-os`. Ce binaire appartient à Anthropic : il n'est ni commité ni redistribué par ce dépôt.

## Comment le projet est écrit

C'est un projet d'apprentissage mené avec Claude Code : Claude écrit le code, David apprend en le lisant. Chaque choix de conception retient l'option des noyaux modernes (Linux, sauf raison contraire), et le commentaire explique les options écartées et pourquoi. L'historique git se lit étape par étape, un commit par changement logique.

## Licence

[Apache 2.0](LICENSE).
