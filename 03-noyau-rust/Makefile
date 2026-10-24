# Étape 3 : notre chargeur (boot.asm) + un noyau écrit en Rust (noyau/)
#   make        -> compile le noyau, assemble le chargeur, colle les deux dans boot.bin
#   make run    -> démarre dans QEMU avec une fenêtre (port série dans le terminal)
#   make texte  -> même chose, mais l'écran VGA s'affiche dans le terminal
#                  (pratique dans un conteneur sans fenêtre ; quitter : Echap puis 2, puis « quit »)
#   make test   -> démarre sans écran pendant 2 s, puis affiche serial.log
#   make debug  -> sans écran, journalise exceptions et reset du CPU dans qemu.log
#   make capture -> démarre sans écran, puis enregistre l'écran dans ecran.png
#   make gdb    -> QEMU figé au démarrage, en attente de GDB sur le port 1234
#   make dump   -> affiche l'image octet par octet
#   make clean  -> supprime les fichiers générés
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

clean:
	rm -f boot.bin chargeur.bin noyau.bin serial.log qemu.log ecran.png
	cd noyau && cargo clean

.PHONY: run texte test debug capture gdb dump clean FORCE
