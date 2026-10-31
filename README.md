# claude-os

[![QEMU](https://github.com/Movida/claude-os/actions/workflows/qemu.yml/badge.svg)](https://github.com/Movida/claude-os/actions/workflows/qemu.yml)

Un OS x86 écrit de zéro, brique par brique, pour apprendre comment tout fonctionne au plus bas niveau. Son but à terme : faire tourner le vrai Claude Code.

> *A from-scratch x86 operating system, built step by step as a learning project: NASM boot sector, `no_std` Rust kernel, a WebAssembly/WASI runtime as the native program format, and a minimal Linux compatibility layer whose goal is to run the real, unmodified `claude` binary. Code and comments are in French.*

## Où en est le projet

`claude --version` tourne dans le noyau : le binaire officiel de Claude Code, un ELF x86_64 dynamique, chargé avec ld-linux et la glibc de la machine, sans aucune modification.

```
[16 bits] Noyau lu sur le disque, recopie a 1 Mio en mode irreel.
[64 bits] Mode long actif !
[noyau] Bonjour depuis le noyau Rust !
...
```

## Architecture

- **Démarrage** : notre propre chargeur en assembleur (BIOS legacy), passage du mode réel 16 bits au mode protégé 32 bits puis au mode long 64 bits.
- **Noyau Rust** `no_std` : interruptions, horloge, clavier, pagination W^X, allocateur buddy, mémoire virtuelle à la demande, système de fichiers en mémoire. Aucune crate qui fait le travail à notre place : seulement `core` et `alloc`, avec notre propre allocateur.
- **WebAssembly est le format natif des programmes** : le noyau embarque un interpréteur Wasm, testé contre la suite officielle de WebAssembly, avec WASI comme interface système (isolation à la façon de Nebulet).
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

La feuille de route complète (ordonnanceur, réseau, TCP, terminal, shell…) est dans [`CLAUDE.md`](CLAUDE.md), et le récit des décisions dans [`HISTORIQUE.md`](HISTORIQUE.md).

## Essayer

Outils : `nasm`, `qemu-system-x86_64`, `gcc`, `libc6-dev`, et Rust via `rustup` (la version est figée dans `rust-toolchain.toml`). Le plus simple est d'ouvrir le dépôt dans son devcontainer (`.devcontainer/`), qui installe tout.

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

[MIT](LICENSE).
