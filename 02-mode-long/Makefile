# Étape 2b : passage en mode long 64 bits (chargeur en deux temps)
#   make        -> assemble boot.bin (plusieurs secteurs : 1er étage + 2e étage)
#   make run    -> démarre dans QEMU avec une fenêtre (port série dans le terminal)
#   make texte  -> même chose, mais l'écran VGA s'affiche dans le terminal
#                  (pratique dans un conteneur sans fenêtre ; quitter : Echap puis 2, puis « quit »)
#   make test   -> démarre sans écran pendant 2 s, puis affiche serial.log
#   make debug  -> sans écran, journalise exceptions et reset du CPU dans qemu.log
#                  (-no-reboot : QEMU s'arrête au lieu de redémarrer en boucle)
#   make capture -> démarre sans écran, puis enregistre l'écran dans ecran.png
#   make gdb    -> QEMU figé au démarrage, en attente de GDB sur le port 1234
#   make dump   -> affiche l'image octet par octet (55 AA à 0x1FE, puis le 2e étage à 0x200)
#   make clean  -> supprime les fichiers générés

QEMU = qemu-system-x86_64 -drive format=raw,file=boot.bin
# Socket du moniteur QEMU dans /tmp : un dossier réseau ne sait pas en héberger.
MON  = /tmp/qemu-mon-os.sock

boot.bin: boot.asm
	nasm -f bin boot.asm -o boot.bin

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

# Le moniteur QEMU (une console de contrôle) écoute sur une socket Unix ;
# on lui envoie la commande « screendump » après 1 s de démarrage.
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
	rm -f boot.bin serial.log qemu.log ecran.png

.PHONY: run texte test debug capture gdb dump clean
