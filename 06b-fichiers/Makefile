# Sous-étape 6b : les fichiers. Un système de fichiers en mémoire (le tmpfs
# de Linux, fichiers/), où l'archive est déballée, les descripteurs, et les
# fichiers projetés en mémoire. Le reste vient de 6a (la mémoire virtuelle
# à la demande, zones/) et de l'étape 5 : le noyau (noyau/) exécute des
# binaires Linux et garde l'interpréteur WebAssembly de l'étape 4 (wasm/) ;
# il est lancé par notre chargeur (boot.asm), qui le lit par morceaux, en
# mode irréel.
#   make        -> compile le noyau et les programmes, fabrique l'archive,
#                  assemble le chargeur, colle les trois dans boot.bin
#   make run    -> démarre dans QEMU avec une fenêtre (port série dans le terminal)
#   make texte  -> même chose, mais l'écran VGA s'affiche dans le terminal
#                  (pratique dans un conteneur sans fenêtre ; quitter : Echap puis 2, puis « quit »)
#   make test   -> démarre sans écran (DUREE secondes), puis affiche serial.log
#   make duree  -> le temps qu'il faut laisser au démarrage (pour verifier.sh)
#   make debug  -> sans écran, journalise exceptions et reset du CPU dans qemu.log
#   make capture -> démarre sans écran, puis enregistre l'écran dans ecran.png
#   make gdb    -> QEMU figé au démarrage, en attente de GDB sur le port 1234
#   make dump   -> affiche l'image octet par octet
#   make trace  -> démarre un noyau qui affiche chaque appel système des
#                  programmes Linux (comme strace), puis montre ceux de
#                  bonjour-c sous Linux, sur l'hôte, avec strace, pour comparer
#   make tests-qemu -> les scénarios dans QEMU : un noyau qui déborde exprès
#                  de sa pile doit le dire (page de garde, double faute) ;
#                  un noyau gonflé au-delà de 1 Mio doit être lu en entier
#   make tests-hote -> les tests sur la machine hôte : ceux de la
#                  bibliothèque des formats (formats/ : archive cpio,
#                  exécutables ELF, essayés aussi sur de vrais programmes
#                  Linux, dont un gcc -static) ; ceux de la carte des zones
#                  (zones/ : des cas écrits à la main, puis des milliers
#                  d'opérations au hasard comparées à un modèle) ; ceux du
#                  système de fichiers (fichiers/ : une règle de Linux par
#                  cas, puis des milliers d'opérations au hasard comparées
#                  à un modèle naïf) ; puis
#                  pour l'interpréteur WebAssembly, télécharge et
#                  convertit la suite de tests officielle si besoin, puis la
#                  rejoue contre la bibliothèque (tableau par fichier) ;
#                  vérifie aussi que les quatre bibliothèques se compilent
#                  pour le noyau (no_std), sans avertissement ; enfin
#                  lance linux/memoire sur l'hôte : nos codes d'erreur de
#                  mmap & co. doivent être ceux du vrai Linux ; et
#                  linux/claude-version, qui doit y réussir aussi, comme
#                  linux/temps (les horloges) et linux/fichiers (nos codes
#                  d'erreur des fichiers doivent être ceux de Linux)
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
#   - pile : nasm puis ld, affiche ce qu'il trouve sur sa pile initiale ;
#   - sse : nasm puis ld, un calcul en SSE2 ;
#   - bonjour-c : gcc -static, avec la glibc de la machine (libc.a, du
#     paquet libc6-dev). -O2 et les avertissements, comme un programme
#     ordinaire ;
#   - memoire : gcc -static, les appels de la mémoire (mmap, munmap,
#     mprotect, madvise) contre ce qu'en fait Linux : make tests-hote le
#     lance aussi sur l'hôte, où chaque vérification doit dire « ok » ;
#   - claude-version : gcc -static, la séquence mémoire de
#     `claude --version` (relevée par strace), rejouée ; sur l'hôte aussi ;
#   - temps : gcc -static, les horloges (clock_gettime...), sur l'hôte
#     aussi ;
#   - fichiers : gcc -static, les appels des fichiers contre ce qu'en fait
#     Linux, comme memoire ; sur l'hôte aussi ;
#   - arbre : gcc -static, liste /etc, /home et /dev ;
#   - segments : gcc -static, ses propres segments projetés depuis son
#     fichier (MADV_DONTNEED relit le fichier) ; sur l'hôte aussi.
# Pour les tests du lecteur ELF sur l'hôte, une variante qu'il doit
# accepter, bonjour-c-deux-segments (gcc -static -z noseparate-code : code
# et données dans deux segments seulement, la disposition d'avant binutils
# 2.31), et des variantes qu'il doit refuser : bonjour-c-pie
# (gcc -static-pie, un ET_DYN),
# bonjour-c-dynamique (gcc sans option : ET_DYN, ld-linux et la glibc
# partagée), bonjour-asm-wx (ld -N, un segment W+X) ; et
# bonjour-asm-pile-executable (ld -z execstack), dont il doit lire le
# PT_GNU_STACK.
LINUX = linux/construits
CFLAGS_LINUX = -O2 -Wall -Wextra -Werror

$(LINUX)/bonjour-asm.o: linux/bonjour.asm
	mkdir -p $(LINUX)
	nasm -f elf64 $< -o $@

$(LINUX)/bonjour-asm: $(LINUX)/bonjour-asm.o
	ld -o $@ $<

$(LINUX)/pile.o: linux/pile.asm
	mkdir -p $(LINUX)
	nasm -f elf64 $< -o $@

$(LINUX)/pile: $(LINUX)/pile.o
	ld -o $@ $<

$(LINUX)/sse.o: linux/sse.asm
	mkdir -p $(LINUX)
	nasm -f elf64 $< -o $@

$(LINUX)/sse: $(LINUX)/sse.o
	ld -o $@ $<

$(LINUX)/bonjour-asm-wx: $(LINUX)/bonjour-asm.o
	ld -N -o $@ $< 2>/dev/null

$(LINUX)/bonjour-asm-pile-executable: $(LINUX)/bonjour-asm.o
	ld -z execstack -o $@ $<

$(LINUX)/bonjour-c: linux/bonjour.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/memoire: linux/memoire.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/claude-version: linux/claude-version.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/temps: linux/temps.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/fichiers: linux/fichiers.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/arbre: linux/arbre.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/segments: linux/segments.c
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

# Les programmes de test de `make tests-qemu` (linux/tests/) : chacun fait
# une faute que le noyau doit arrêter, ou essaie de mauvais appels système
# (mmx-ecrit puis mmx-lit : un programme ne doit rien trouver, dans les
# registres x87, MMX et SSE, de ce qu'y a laissé le précédent) ; zero et
# grande-pile font au contraire des fautes que le noyau doit SERVIR (la
# page de zéros et la copie à l'écriture, la pile qui grandit jusqu'à
# 8 Mio), pile-executable (lié avec ld -z execstack) exécute du code posé
# sur sa pile ; oom touche plus de mémoire que la machine n'en a, et doit être
# tué par le noyau, qui doit ensuite tout récupérer ; puis des
# exécutables que le noyau doit refuser :
#   - wx : un segment W+X (ld -N) ;
#   - derniere-page : des segments dans les dernières pages de la moitié
#     basse (là où est la pile, et dans la page interdite) ;
#   - et-dyn : un exécutable indépendant de la position (ld -pie) ;
#   - tronque : les 40 premiers octets d'un exécutable.
# Enfin bonjour-asm, pour montrer que le noyau exécute encore des
# programmes après tout cela.
TESTS_LINUX = mmx-ecrit mmx-lit pointeurs tas mprotect ecrire-code executer-pile lire-noyau lire-zero hlt int80 icebp pas-a-pas mov-ss sgdt \
              zero grande-pile pile-executable recursion oom boucle brk-boucle \
              wx derniere-page et-dyn tronque bus-fichier

$(LINUX)/tests/%.o: linux/tests/%.asm linux/tests/commun.inc
	mkdir -p $(LINUX)/tests
	nasm -f elf64 -i linux/tests/ $< -o $@

$(LINUX)/tests/%: $(LINUX)/tests/%.o
	ld -o $@ $<

$(LINUX)/tests/pile-executable: $(LINUX)/tests/pile-executable.o
	ld -z execstack -o $@ $<

$(LINUX)/tests/wx: $(LINUX)/bonjour-asm.o
	mkdir -p $(LINUX)/tests
	ld -N -o $@ $< 2>/dev/null

$(LINUX)/tests/derniere-page: $(LINUX)/bonjour-asm.o
	mkdir -p $(LINUX)/tests
	ld -Ttext=0x7ffffffff000 -o $@ $<

$(LINUX)/tests/et-dyn: $(LINUX)/bonjour-asm.o
	mkdir -p $(LINUX)/tests
	ld -pie --no-dynamic-linker -o $@ $<

$(LINUX)/tests/tronque: $(LINUX)/bonjour-asm
	mkdir -p $(LINUX)/tests
	head -c 40 $< > $@

# L'archive des programmes de test : sa description est fabriquée ici, une
# ligne par programme (voir archive.sh).
tests.cpio: archive.sh $(addprefix $(LINUX)/tests/,$(TESTS_LINUX)) $(LINUX)/bonjour-asm
	{ echo "dir /bin 755 0 0"; \
	  for p in $(TESTS_LINUX); do echo "file /bin/$$p $(LINUX)/tests/$$p 755 0 0"; done; \
	  echo "file /bin/bonjour-asm $(LINUX)/bonjour-asm 755 0 0"; } | sh archive.sh $@ -

PROGRAMMES_HOTE = $(addprefix $(LINUX)/,bonjour-asm bonjour-asm.o bonjour-asm-wx bonjour-asm-pile-executable bonjour-c bonjour-c-deux-segments bonjour-c-pie bonjour-c-dynamique)

# L'archive de démarrage, décrite par archive.txt : le noyau la déballe,
# puis exécute les programmes de /bin dans l'ordre (voir archive.sh).
programmes.cpio: archive.sh archive.txt racine/etc/bonjour.txt $(LINUX)/bonjour-asm $(LINUX)/pile $(LINUX)/sse $(LINUX)/bonjour-c $(LINUX)/memoire $(LINUX)/claude-version $(LINUX)/temps $(LINUX)/fichiers $(LINUX)/arbre $(LINUX)/segments FORCE
	cd bonjour && cargo build --release
	cd lecteur && cargo build --release
	sh archive.sh $@ archive.txt

FORCE:

run: boot.bin
	$(QEMU) -serial stdio

texte: boot.bin
	$(QEMU) -display curses -serial file:serial.log

# Le temps que met l'étape à démarrer et à exécuter toute son archive,
# sous QEMU sans accélération, avec de la marge (le BIOS lit l'archive
# secteur par secteur : 2,5 s mesurées ici en 6b). verifier.sh le demande
# par `make duree`.
DUREE = 5

duree:
	@echo $(DUREE)

test: boot.bin
	-timeout $(DUREE) $(QEMU) -display none -no-reboot -serial file:serial.log
	@cat serial.log

debug: boot.bin
	-timeout $(DUREE) $(QEMU) -display none -no-reboot -serial file:serial.log \
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

tests-hote: $(SUITE)/.convertie $(PROGRAMMES_HOTE) $(LINUX)/memoire $(LINUX)/claude-version $(LINUX)/temps $(LINUX)/fichiers $(LINUX)/segments
	cd formats && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd formats && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd zones && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd zones && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd fichiers && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd fichiers && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd wasm && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd wasm && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd wasm && cargo test --release -q -- --nocapture suite_officielle 2>/dev/null | grep -v '^running\|^test \|^$$'
	./$(LINUX)/memoire | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/claude-version | tee /dev/stderr | grep -q "rejouee : ok"
	./$(LINUX)/temps | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/fichiers | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/segments | tee /dev/stderr | (! grep -q ECHEC)

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
#     entier, chaque secteur à sa place ;
#   - test-programmes : l'archive des programmes de test (tests.cpio),
#     exécutés un par un en un seul démarrage ; le noyau doit arrêter
#     chaque programme fautif et continuer, puis éteindre QEMU (le
#     périphérique isa-debug-exit : QEMU sort avec le code 2 x valeur + 1).
#     Chaque ligne de tests-attendu.txt doit être dans ce qu'il affiche.
#     Deux fois : avec le processeur par défaut (qemu64), puis avec toutes
#     les fonctions que QEMU sait imiter (-cpu max : SMEP, SMAP, UMIP...),
#     pour passer aussi par les chemins « si le processeur l'a » ; avec, en
#     plus, les lignes propres à chacun (tests-attendu-qemu64.txt,
#     tests-attendu-max.txt).
QEMU_TEST = timeout $(DUREE) qemu-system-x86_64 -display none -no-reboot
QEMU_PROGRAMMES = timeout 30 qemu-system-x86_64 -display none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 -drive format=raw,file=test-programmes.bin

tests-qemu: test-garde.bin test-gros.bin test-programmes.bin
	-$(QEMU_TEST) -drive format=raw,file=test-garde.bin -serial file:test-garde.log
	grep -F "debordement de la pile du noyau" test-garde.log
	-$(QEMU_TEST) -drive format=raw,file=test-gros.bin -serial file:test-gros.log
	grep -F "chaque secteur a sa place : ok" test-gros.log
	for cpu in qemu64 max; do \
	  $(QEMU_PROGRAMMES) -cpu $$cpu -serial file:test-programmes-$$cpu.log; code=$$?; \
	  [ $$code -eq 1 ] || { echo "-cpu $$cpu : QEMU n'a pas ete eteint par le noyau (code $$code)"; exit 1; }; \
	  while IFS= read -r ligne; do \
	    grep -qF -- "$$ligne" test-programmes-$$cpu.log || { echo "-cpu $$cpu : manque « $$ligne »"; exit 1; }; \
	  done < tests-attendu.txt; \
	  while IFS= read -r ligne; do \
	    grep -qF -- "$$ligne" test-programmes-$$cpu.log || { echo "-cpu $$cpu : manque « $$ligne »"; exit 1; }; \
	  done < tests-attendu-$$cpu.txt; \
	done

# La trace des appels système : le noyau construit avec la fonctionnalité
# trace (son propre dossier de compilation), l'archive ordinaire.
trace: test-trace.bin
	-timeout 5 qemu-system-x86_64 -display none -no-reboot -drive format=raw,file=test-trace.bin -serial file:trace.log
	@echo "--- dans notre noyau ---"
	@sed -n '/bonjour-c : programme/,/bonjour-c : termine/p' trace.log | grep -E '^\[(trace|linux)\]|bonjour-c :'
	@echo "--- sous Linux, sur l'hote (strace) ---"
	@strace ./$(LINUX)/bonjour-c 2>&1 >/dev/null | grep -v "^execve"

test-trace.bin: programmes.cpio FORCE
	cd noyau && cargo build --release --features trace --target-dir target/test-trace 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-trace/x86_64-unknown-none/release/noyau,programmes.cpio,test-trace)

test-programmes.bin: tests.cpio FORCE
	cd noyau && cargo build --release --features test-programmes --target-dir target/test-programmes 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-programmes/x86_64-unknown-none/release/noyau,tests.cpio,test-programmes)

test-%.bin: programmes.cpio FORCE
	cd noyau && cargo build --release --features test-$* --target-dir target/test-$* 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-$*/x86_64-unknown-none/release/noyau,programmes.cpio,test-$*)

clean:
	rm -f boot*.bin test-*.bin programmes.cpio tests.cpio serial.log trace.log qemu.log ecran.png test-*.log
	rm -rf $(LINUX)
	rm -rf $(SUITE)
	cd noyau && cargo clean
	cd wasm && cargo clean
	cd bonjour && cargo clean
	cd lecteur && cargo clean
	cd formats && cargo clean
	cd zones && cargo clean
	cd fichiers && cargo clean

.PHONY: run texte test duree debug capture gdb dump trace tests-hote tests-qemu suite clean FORCE
