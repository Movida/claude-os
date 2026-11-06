#!/bin/sh
# Compile qemu-system-x86_64 (une seule cible : quelques minutes) et l'installe sous
# le préfixe donné. Le Dockerfile et la CI s'en servent ; les dépendances de la
# compilation sont à eux (leur liste de paquets).
#
# Pourquoi pas le paquet d'Ubuntu 24.04 : il en est à QEMU 8.2.2, dont `tb_record` et
# `tb_remove` (accel/tcg/tb-maint.c) calculent `pindex1` d'après `paddr0` : la deuxième
# page d'un bloc traduit à cheval sur deux pages n'est jamais enregistrée, et écrire
# dans cette page n'invalide pas le bloc. Le compilateur à la volée de `claude` patche
# ainsi ses appels directs : il plantait une fois sur quarante environ, sous notre
# noyau comme sous le vrai Linux (HISTORIQUE.md, 6h ; le test : linux/autocode.c).
# Corrigé en amont dès la 8.2.3, jamais repris par Ubuntu.
#
# Pourquoi la 8.2.10 : la dernière de cette même série, qui ne reçoit que des
# corrections ; toutes nos étapes y gardent la machine sur laquelle elles ont été
# vérifiées. Écarté : la dernière version de QEMU, dont les changements (les machines,
# TCG) n'ont rien à voir avec ce bogue, et que rien ne demande pour l'instant ; ou
# une archive d'Ubuntu plus récente, qui entraînerait ses propres bibliothèques.
#
# Une version figée, vérifiée par son SHA-256, comme wabt et la suite de tests de Wasm.
set -eu

VERSION=8.2.10
SHA256=37b4a643da8ed6015eef35f5d7f06e7259d9c95359965a0a98e9667c621ab2bb

prefixe=${1:?usage : construire-qemu.sh PREFIXE}
travail=$(mktemp -d)
trap 'rm -rf "$travail"' EXIT
cd "$travail"
curl -sSfL -o qemu.tar.xz "https://download.qemu.org/qemu-$VERSION.tar.xz"
echo "$SHA256  qemu.tar.xz" | sha256sum -c -
tar -xf qemu.tar.xz
cd "qemu-$VERSION"
# Ce que demandent nos Makefile, et que `--enable` fait échouer si les paquets manquent,
# plutôt qu'une cible qui casse plus tard : le réseau « utilisateur » (slirp), l'écran
# dans le terminal (curses, `make texte`) et les captures (PNG, `make capture`).
./configure --prefix="$prefixe" --target-list=x86_64-softmmu \
    --enable-slirp --enable-curses --enable-png \
    --disable-docs --disable-tools --disable-guest-agent --disable-werror
make -j"$(nproc)"
make install
"$prefixe/bin/qemu-system-x86_64" --version
