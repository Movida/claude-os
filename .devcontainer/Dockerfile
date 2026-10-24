# Environnement de développement de l'OS : assembleur, émulateur, débogueur,
# et Rust pour le noyau. Depuis l'étape 5 : un compilateur C et la glibc
# statique (libc.a, dans libc6-dev), pour compiler les programmes Linux de
# test (`gcc -static`), et strace, pour comparer leurs appels système à ce
# que voit notre noyau.
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends \
        nasm \
        qemu-system-x86 \
        gdb \
        make \
        netcat-openbsd \
        xxd \
        curl \
        ca-certificates \
        gcc \
        libc6-dev \
        strace \
    && rm -rf /var/lib/apt/lists/*

# rustup, pour l'utilisateur du conteneur, sans version de Rust : la version
# exacte est figée dans 03-noyau-rust/noyau/rust-toolchain.toml, et rustup
# l'installe à la première commande cargo lancée dans ce dossier.
USER vscode
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
ENV PATH="/home/vscode/.cargo/bin:${PATH}"
USER root
