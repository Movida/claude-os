# Étape 5 : exécuter un binaire Linux. Le noyau (noyau/) garde
# l'interpréteur WebAssembly de l'étape 4 (wasm/) ; il est lancé par notre
# chargeur (boot.asm), qui le lit par morceaux, en mode irréel.
#   make        -> compile le noyau et les programmes, fabrique l'archive,
#                  assemble le chargeur, colle les trois dans boot.bin
#   make run    -> démarre dans QEMU avec une fenêtre (port série dans le terminal)
#   make texte  -> même chose, mais l'écran VGA s'affiche dans le terminal
#                  (pratique dans un conteneur sans fenêtre ; quitter : Echap puis 2, puis « quit »)
#   make test   -> démarre sans écran pendant 2 s, puis affiche serial.log
#   make debug  -> sans écran, journalise exceptions et reset du CPU dans qemu.log
#   make capture -> démarre sans écran, puis enregistre l'écran dans ecran.png
#   make gdb    -> QEMU figé au démarrage, en attente de GDB sur le port 1234
#   make dump   -> affiche l'image octet par octet
#   make tests-qemu -> les scénarios dans QEMU : un noyau qui déborde exprès
#                  de sa pile doit le dire (page de garde, double faute) ;
#                  un noyau gonflé au-delà de 1 Mio doit être lu en entier
#   make tests-hote -> les tests sur la machine hôte : ceux de la
#                  bibliothèque des formats (formats/ : archive cpio,
#                  exécutables ELF, essayés aussi sur de vrais programmes
#                  Linux, dont un gcc -static) ; puis
#                  pour l'interpréteur WebAssembly, télécharge et
#                  convertit la suite de tests officielle si besoin, puis la
#                  rejoue contre la bibliothèque (tableau par fichier) ;
#                  vérifie aussi que les deux bibliothèques se compilent
#                  pour le noyau (no_std), sans avertissement
#   make suite  -> seulement télécharger et convertir la suite
#   make clean  -> supprime les fichiers générés, la suite, wabt et la compilation
#
# L'image disque : secteur 0 = 1er étage, puis le 2e étage, puis le noyau,
# puis l'archive de programmes, chacun complété au secteur.

QEMU = qemu-system-x86_64 -drive format=raw,file=boot.bin
MON  = /tmp/qemu-mon-os.sock
NOYAU_ELF = noyau/target/x86_64-unknown-none/release/noyau
# Le programme WebAssembly de l'archive (bonjour/, compilé par rustc pour
# la cible wasm32-unknown-unknown).
BONJOUR = bonjour/target/wasm32-unknown-unknown/release/bonjour.wasm

# Assemble une image disque : $(call image,ELF du noyau,archive,NOM) écrit
# NOM.bin, en passant par NOM-noyau.bin, NOM-archive.bin et
# NOM-chargeur.bin.
#   - objcopy -O binary retire les en-têtes ELF du noyau et ne garde que
#     les octets à recopier en mémoire, à partir de 1 Mio ; truncate
#     complète au secteur ;
#   - le chargeur doit savoir combien de secteurs lire (NOYAU_SECTEURS),
#     où s'arrête le noyau en mémoire une fois sa .bss et ses piles
#     comptées (NOYAU_MEMOIRE, l'adresse du symbole __bss_fin de
#     linker.ld, moins celle du début du noyau), et la taille de
#     l'archive (ARCHIVE_OCTETS). Si nm ne trouve pas __bss_fin (le
#     symbole renommé, un noyau dépouillé), on s'arrête : bash calculerait
#     sans broncher 0x - 0xffffffff80100000, près de 2 Gio.
define image
	objcopy -O binary $(1) $(3)-noyau.bin
	truncate -s %512 $(3)-noyau.bin
	cp $(2) $(3)-archive.bin
	truncate -s %512 $(3)-archive.bin
	fin=$$(nm -P $(1) | awk '$$1 == "__bss_fin" { print $$3 }'); \
	test -n "$$fin" || { echo "__bss_fin introuvable dans $(1)"; exit 1; }; \
	nasm -f bin \
	  -D NOYAU_SECTEURS=$$(( $$(stat -c %s $(3)-noyau.bin) / 512 )) \
	  -D NOYAU_MEMOIRE=$$(( 0x$$fin - 0xffffffff80100000 )) \
	  -D ARCHIVE_OCTETS=$$(stat -c %s $(2)) \
	  boot.asm -o $(3)-chargeur.bin
	cat $(3)-chargeur.bin $(3)-noyau.bin $(3)-archive.bin > $(3).bin
endef

# cargo décide lui-même s'il faut recompiler : on l'appelle à chaque fois.
boot.bin: programmes.cpio FORCE
	cd noyau && cargo build --release
	$(call image,$(NOYAU_ELF),programmes.cpio,boot)

# Les programmes Linux de test (linux/), construits dans linux/construits/.
# Ils tournent aussi tels quels sous Linux, sur la machine hôte.
#   - bonjour-asm : nasm puis ld, sans bibliothèque C ;
#   - bonjour-c : gcc -static, avec la glibc de la machine (libc.a, du
#     paquet libc6-dev). -O2 et les avertissements, comme un programme
#     ordinaire.
# Pour les tests du lecteur ELF sur l'hôte, une variante qu'il doit
# accepter, bonjour-c-deux-segments (gcc -static -z noseparate-code : code
# et données dans deux segments seulement, la disposition d'avant binutils
# 2.31), et des variantes qu'il doit refuser : bonjour-c-pie
# (gcc -static-pie, un ET_DYN),
# bonjour-c-dynamique (gcc sans option : ET_DYN, ld-linux et la glibc
# partagée), bonjour-asm-wx (ld -N, un segment W+X).
LINUX = linux/construits
CFLAGS_LINUX = -O2 -Wall -Wextra -Werror

$(LINUX)/bonjour-asm.o: linux/bonjour.asm
	mkdir -p $(LINUX)
	nasm -f elf64 $< -o $@

$(LINUX)/bonjour-asm: $(LINUX)/bonjour-asm.o
	ld -o $@ $<

$(LINUX)/bonjour-asm-wx: $(LINUX)/bonjour-asm.o
	ld -N -o $@ $< 2>/dev/null

$(LINUX)/bonjour-c: linux/bonjour.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/bonjour-c-deux-segments: linux/bonjour.c
	mkdir -p $(LINUX)
	gcc -static -Wl,-z,noseparate-code $(CFLAGS_LINUX) $< -o $@

$(LINUX)/bonjour-c-pie: linux/bonjour.c
	mkdir -p $(LINUX)
	gcc -static-pie $(CFLAGS_LINUX) $< -o $@

$(LINUX)/bonjour-c-dynamique: linux/bonjour.c
	mkdir -p $(LINUX)
	gcc $(CFLAGS_LINUX) $< -o $@

PROGRAMMES_HOTE = $(addprefix $(LINUX)/,bonjour-asm bonjour-asm.o bonjour-asm-wx bonjour-c bonjour-c-deux-segments bonjour-c-pie bonjour-c-dynamique)

# L'archive de programmes, que le noyau exécute dans l'ordre (voir
# archive.sh).
programmes.cpio: archive.sh $(LINUX)/bonjour-asm FORCE
	cd bonjour && cargo build --release
	sh archive.sh $@ $(BONJOUR) $(LINUX)/bonjour-asm

FORCE:

run: boot.bin
	$(QEMU) -serial stdio

texte: boot.bin
	$(QEMU) -display curses -serial file:serial.log

test: boot.bin
	-timeout 2 $(QEMU) -display none -no-reboot -serial file:serial.log
	@cat serial.log

debug: boot.bin
	-timeout 2 $(QEMU) -display none -no-reboot -serial file:serial.log \
	  -d int,cpu_reset -D qemu.log
	@cat serial.log
	@echo "--- exceptions (v=numero, e=code d'erreur) ---"
	@grep -E "^ *[0-9]+: v=|Triple fault" qemu.log | grep -v "v=08 e=0000 i=1" | head -20 || true

capture: boot.bin
	rm -f $(MON) ecran.png
	-timeout 3 $(QEMU) -display none -serial null \
	  -monitor unix:$(MON),server,nowait & \
	sleep 1.5; echo "screendump ecran.png -f png" | nc -U -q1 $(MON) >/dev/null; wait
	@ls ecran.png

gdb: boot.bin
	$(QEMU) -serial stdio -s -S

dump: boot.bin
	od -A x -t x1 -v boot.bin

# La suite de tests de la spécification WebAssembly 2.0 (tag wg-2.0 du dépôt
# WebAssembly/spec), à une version figée : l'empreinte SHA-256 garantit que
# tout le monde (la VM de David, la CI) teste exactement les mêmes fichiers.
SPEC_URL    = https://github.com/WebAssembly/spec/archive/refs/tags/wg-2.0.tar.gz
SPEC_SHA256 = 263aef470fbe49aca2687f5996fee9f8f550944f613769b3fa708eb6d0ceb846

# wast2json, de wabt (WebAssembly Binary Toolkit), convertit les .wast de
# la suite en modules .wasm et en commandes .json. On télécharge lui aussi
# sa version officielle (un binaire pour Linux x86_64, comme la VM de David
# et la CI), figée et vérifiée : celle des distributions (1.0.34 dans
# Ubuntu 24.04) ne lit pas deux fichiers de la suite (un commentaire en fin
# de fichier, un `if` sans `then`), et la conversion ne dépend plus de la
# machine.
WABT_VERSION = 1.0.39
WABT_URL     = https://github.com/WebAssembly/wabt/releases/download/$(WABT_VERSION)/wabt-$(WABT_VERSION)-linux-x64.tar.gz
WABT_SHA256  = 1df1254b6639f5f1f89665907ee8cd0cd30114f40483515e583cccb86240840f

SUITE = suite
WAST2JSON = $(SUITE)/wabt-$(WABT_VERSION)/bin/wast2json

# Les commandes de test passent par des tuyaux (`cargo ... | tee ... | grep`)
# dont le code de sortie est, par défaut, celui de la DERNIÈRE commande : un
# test en échec passerait inaperçu, et la CI resterait verte. pipefail rend
# le tuyau en échec dès qu'une de ses commandes échoue (option de bash, que
# le sh de Debian et d'Ubuntu n'a pas).
SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

# Une recette qui échoue efface ce qu'elle a commencé d'écrire : une
# archive à moitié écrite (archive.sh interrompu), plus récente que ses
# sources, servirait sinon telle quelle à la construction suivante.
.DELETE_ON_ERROR:

tests-hote: $(SUITE)/.convertie $(PROGRAMMES_HOTE)
	cd formats && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd formats && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd wasm && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd wasm && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd wasm && cargo test --release -q -- --nocapture suite_officielle 2>/dev/null | grep -v '^running\|^test \|^$$'

suite: $(SUITE)/.convertie

# La conversion dépend de wast2json : un autre wabt la refait, en effaçant
# d'abord ce que l'ancien avait produit.
$(SUITE)/.convertie: $(WAST2JSON)
	curl -sSfL $(SPEC_URL) -o $(SUITE)/spec.tar.gz
	echo "$(SPEC_SHA256)  $(SUITE)/spec.tar.gz" | sha256sum -c --quiet
	cd $(SUITE) && rm -f *.wast *.json *.wasm *.wat
	tar xzf $(SUITE)/spec.tar.gz -C $(SUITE) --strip-components=3 --wildcards --no-wildcards-match-slash 'spec-wg-2.0/test/core/*.wast'
	cd $(SUITE) && for f in *.wast; do \
	  ./wabt-$(WABT_VERSION)/bin/wast2json "$$f" -o "$${f%.wast}.json" || exit 1; \
	done
	touch $@

$(WAST2JSON):
	mkdir -p $(SUITE)
	curl -sSfL $(WABT_URL) -o $(SUITE)/wabt.tar.gz
	echo "$(WABT_SHA256)  $(SUITE)/wabt.tar.gz" | sha256sum -c --quiet
	tar xzf $(SUITE)/wabt.tar.gz -C $(SUITE) wabt-$(WABT_VERSION)/bin/wast2json
	touch $@

# Les scénarios de `make tests-qemu` : chacun un noyau construit avec la
# fonctionnalité test-NOM (dans son propre dossier de compilation, pour ne
# pas défaire celle du noyau normal), qui provoque exprès une situation à
# vérifier, et dont on cherche la conclusion dans ce qu'il affiche :
#   - test-garde : déborder de la pile, que la page de garde doit arrêter
#     net, et le dire ;
#   - test-gros : un noyau de plus de 1 Mio, que le chargeur doit lire en
#     entier, chaque secteur à sa place.
QEMU_TEST = timeout 2 qemu-system-x86_64 -display none -no-reboot

tests-qemu: test-garde.bin test-gros.bin
	-$(QEMU_TEST) -drive format=raw,file=test-garde.bin -serial file:test-garde.log
	grep -F "debordement de la pile du noyau" test-garde.log
	-$(QEMU_TEST) -drive format=raw,file=test-gros.bin -serial file:test-gros.log
	grep -F "chaque secteur a sa place : ok" test-gros.log

test-%.bin: programmes.cpio FORCE
	cd noyau && cargo build --release --features test-$* --target-dir target/test-$* 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-$*/x86_64-unknown-none/release/noyau,programmes.cpio,test-$*)

clean:
	rm -f boot*.bin test-*.bin programmes.cpio serial.log qemu.log ecran.png test-*.log
	rm -rf $(LINUX)
	rm -rf $(SUITE)
	cd noyau && cargo clean
	cd wasm && cargo clean
	cd bonjour && cargo clean
	cd formats && cargo clean

.PHONY: run texte test debug capture gdb dump tests-hote tests-qemu suite clean FORCE
