# Étape 4 : un interpréteur WebAssembly (wasm/), d'abord testé sur la
# machine hôte, puis exécuté par le noyau (noyau/), lancé par notre chargeur
# (boot.asm).
#   make        -> compile le noyau, assemble le chargeur, colle les deux dans boot.bin
#   make run    -> démarre dans QEMU avec une fenêtre (port série dans le terminal)
#   make texte  -> même chose, mais l'écran VGA s'affiche dans le terminal
#                  (pratique dans un conteneur sans fenêtre ; quitter : Echap puis 2, puis « quit »)
#   make test   -> démarre sans écran pendant 2 s, puis affiche serial.log
#   make debug  -> sans écran, journalise exceptions et reset du CPU dans qemu.log
#   make capture -> démarre sans écran, puis enregistre l'écran dans ecran.png
#   make gdb    -> QEMU figé au démarrage, en attente de GDB sur le port 1234
#   make dump   -> affiche l'image octet par octet
#   make tests-hote -> les tests sur la machine hôte : télécharge et
#                  convertit la suite de tests officielle si besoin, puis la
#                  rejoue contre la bibliothèque (tableau par fichier) ;
#                  vérifie aussi que la bibliothèque se compile pour le
#                  noyau (no_std), sans avertissement
#   make suite  -> seulement télécharger et convertir la suite
#   make clean  -> supprime les fichiers générés, la suite, wabt et la compilation
#
# L'image disque : secteur 0 = 1er étage, puis le 2e étage, puis le noyau.

QEMU = qemu-system-x86_64 -drive format=raw,file=boot.bin
MON  = /tmp/qemu-mon-os.sock
NOYAU_ELF = noyau/target/x86_64-unknown-none/release/noyau

boot.bin: chargeur.bin noyau.bin
	cat chargeur.bin noyau.bin > boot.bin

# Le chargeur doit savoir combien de secteurs lire : on le calcule à partir
# de la taille du noyau compilé, arrondie au secteur supérieur.
chargeur.bin: boot.asm noyau.bin
	nasm -f bin -D NOYAU_SECTEURS=$$(( ($$(stat -c %s noyau.bin) + 511) / 512 )) \
	  boot.asm -o chargeur.bin

# cargo décide lui-même s'il faut recompiler : on l'appelle à chaque fois.
# objcopy -O binary retire les en-têtes ELF et ne garde que les octets à
# copier en mémoire, à partir de 0x100000 ; truncate complète au secteur.
noyau.bin: FORCE
	cd noyau && cargo build --release
	objcopy -O binary $(NOYAU_ELF) noyau.bin
	truncate -s %512 noyau.bin

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

tests-hote: $(SUITE)/.convertie
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

clean:
	rm -f boot.bin chargeur.bin noyau.bin serial.log qemu.log ecran.png
	rm -rf $(SUITE)
	cd noyau && cargo clean
	cd wasm && cargo clean

.PHONY: run texte test debug capture gdb dump tests-hote suite clean FORCE
