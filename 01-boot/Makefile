# Étape 1 : secteur de démarrage
#   make        -> assemble boot.bin (exactement 512 octets)
#   make run    -> démarre dans QEMU avec une fenêtre (écran + port série dans le terminal)
#   make dump   -> affiche l'image octet par octet, pour voir la signature 55 AA
#   make clean  -> supprime les fichiers générés

boot.bin: boot.asm
	nasm -f bin boot.asm -o boot.bin

run: boot.bin
	qemu-system-x86_64 -drive format=raw,file=boot.bin -serial stdio

dump: boot.bin
	od -A x -t x1 -v boot.bin | tail -3

clean:
	rm -f boot.bin

.PHONY: run dump clean
