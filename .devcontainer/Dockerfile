# Environnement de développement de l'OS : assembleur, émulateur, débogueur,
# et Rust pour le noyau. Depuis l'étape 5 : un compilateur C et la glibc
# statique (libc.a, dans libc6-dev), pour compiler les programmes Linux de
# test (`gcc -static`), et strace, pour comparer leurs appels système à ce
# que voit notre noyau. Depuis 6h : QEMU compilé, pas le paquet d'Ubuntu (voir
# construire-qemu.sh) ; d'où glib, pixman, slirp, curses, PNG, ninja, le venv de Python...
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends \
        nasm \
        gdb \
        make \
        netcat-openbsd \
        xxd \
        curl \
        ca-certificates \
        gcc \
        libc6-dev \
        strace \
        libglib2.0-dev \
        libpixman-1-dev \
        libslirp-dev \
        libncurses-dev \
        libpng-dev \
        ninja-build \
        python3-venv \
        pkg-config \
        flex \
        bison \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY construire-qemu.sh /tmp/construire-qemu.sh
RUN sh /tmp/construire-qemu.sh /usr/local && rm /tmp/construire-qemu.sh

# rustup, pour l'utilisateur du conteneur, sans version de Rust : la version
# exacte est figée dans 03-noyau-rust/noyau/rust-toolchain.toml, et rustup
# l'installe à la première commande cargo lancée dans ce dossier.
USER vscode
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
ENV PATH="/home/vscode/.cargo/bin:${PATH}"
USER root

# Le superviseur de Remote Control, processus principal du conteneur
# ("overrideCommand": false, dans devcontainer.json). Il est copié dans l'image
# et non lu dans le dépôt : le dossier de travail change de branche, et un vieux
# commit sans ce script empêcherait le conteneur de démarrer. Le modifier demande
# donc de reconstruire le conteneur.
COPY remote-control.sh /usr/local/bin/remote-control.sh
COPY sacrifiable.sh /usr/local/share/remote-control/sacrifiable.sh
CMD ["/usr/local/bin/remote-control.sh", "/workspaces/claude-os"]
