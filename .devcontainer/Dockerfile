# Environnement de développement de l'OS : assembleur, émulateur, débogueur.
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends \
        nasm \
        qemu-system-x86 \
        gdb \
        make \
        netcat-openbsd \
        xxd \
    && rm -rf /var/lib/apt/lists/*
