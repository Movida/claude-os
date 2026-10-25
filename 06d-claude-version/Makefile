# Sous-étape 6d : claude --version, le vrai binaire de Claude Code. Le
# noyau applique la limite de temps de calcul de Linux (RLIMIT_CPU). Le
# reste vient de 6c (les programmes dynamiques : ld-linux et la glibc
# partagée, le lanceur /etc/demarrage), de 6b (le système de fichiers en
# mémoire, fichiers/, et les fichiers projetés), de 6a (la mémoire
# virtuelle à la demande, zones/) et de l'étape 5 : le noyau (noyau/)
# exécute des binaires Linux et garde l'interpréteur WebAssembly de
# l'étape 4 (wasm/) ; il est lancé par notre chargeur (boot.asm), qui le
# lit par morceaux, en mode irréel.
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
#                  bonjour-c-dynamique (ld-linux et la glibc partagée) sous
#                  Linux, sur l'hôte, avec strace, pour comparer
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
#                  d'erreur des fichiers doivent être ceux de Linux), et
#                  linux/dynamique (ld-linux, la glibc partagée, dlopen),
#                  linux/signaux (nos codes d'erreur des signaux) et
#                  linux/systeme (uname, futex, prctl...)
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
#   - bonjour-c-pie : le même en gcc -static-pie, un ET_DYN sans
#     interpréteur, qui se reloge lui-même (6c) ; bonjour-c-dynamique, le
#     même en gcc sans option, qui demande ld-linux et la glibc partagée ;
#   - dynamique : lié aux cinq bibliothèques de claude, il vérifie ce que
#     font ld-linux et la glibc partagée, et charge libessai.so (dlopen),
#     une bibliothèque à nous (linux/essai.c), installée dans
#     /usr/local/lib ; sur l'hôte aussi (LD_LIBRARY_PATH pour libessai) ;
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
#     fichier (MADV_DONTNEED relit le fichier) ; sur l'hôte aussi ;
#   - signaux : gcc -static, les signaux enregistrés (rt_sigaction,
#     rt_sigprocmask, sigaltstack, kill...) contre ce qu'en fait Linux ;
#     sur l'hôte aussi ;
#   - systeme : gcc -static, les petits appels de claude (uname,
#     sched_getaffinity, futex, prctl) ; sur l'hôte aussi.
# Pour les tests du lecteur ELF sur l'hôte, des variantes qu'il doit
# accepter : bonjour-c-deux-segments (gcc -static -z noseparate-code : code
# et données dans deux segments seulement, la disposition d'avant binutils
# 2.31), bonjour-c-pie (gcc -static-pie, un ET_DYN sans interpréteur) et
# bonjour-c-dynamique (gcc sans option : un ET_DYN qui demande ld-linux et
# la glibc partagée) ; une qu'il doit refuser, bonjour-asm-wx (ld -N, un
# segment W+X) ; et bonjour-asm-pile-executable (ld -z execstack), dont il
# doit lire le PT_GNU_STACK. Les tests lisent aussi ld-linux et la glibc
# partagée de la machine, là où Ubuntu les installe.
LINUX = linux/construits
# La glibc partagée de la machine, copiée dans glibc/ (voir $(GLIBC)/.copiee).
GLIBC_HOTE = /usr/lib/x86_64-linux-gnu
# ld-linux, la glibc, et les quatre autres bibliothèques de `claude`
# (depuis la glibc 2.34, libpthread, libdl et librt sont des coquilles
# presque vides : tout est dans libc.so.6, mais claude les demande).
GLIBC_FICHIERS = ld-linux-x86-64.so.2 libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1
GLIBC = glibc
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

$(LINUX)/signaux: linux/signaux.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/systeme: linux/systeme.c
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

$(LINUX)/libessai.so: linux/essai.c
	mkdir -p $(LINUX)
	gcc -shared -fPIC -Wl,-soname,libessai.so $(CFLAGS_LINUX) $< -o $@

# --no-as-needed : garder les NEEDED des bibliothèques dont le programme
# n'appelle rien, comme claude ; -l: nomme le fichier exact, parce que
# depuis la glibc 2.34, -lpthread, -ldl et -lrt ne trouvent que des
# archives vides (mesuré : aucun NEEDED).
$(LINUX)/dynamique: linux/dynamique.c
	mkdir -p $(LINUX)
	gcc $(CFLAGS_LINUX) $< -o $@ -Wl,--no-as-needed -lm -l:libpthread.so.0 -l:libdl.so.2 -l:librt.so.1

# Les programmes de test de `make tests-qemu` (linux/tests/) : chacun fait
# une faute que le noyau doit arrêter, ou essaie de mauvais appels système
# (mmx-ecrit puis mmx-lit : un programme ne doit rien trouver, dans les
# registres x87, MMX et SSE, de ce qu'y a laissé le précédent) ; zero et
# grande-pile font au contraire des fautes que le noyau doit SERVIR (la
# page de zéros et la copie à l'écriture, la pile qui grandit jusqu'à
# 8 Mio), pile-executable (lié avec ld -z execstack) exécute du code posé
# sur sa pile ; oom touche plus de mémoire que la machine n'en a, et doit être
# tué par le noyau, qui doit ensuite tout récupérer ; boucle et brk-boucle
# se donnent une seconde de calcul (RLIMIT_CPU), et doivent être arrêtés
# par SIGXCPU, limite-egale par SIGKILL (sa limite courante est égale à la
# dure), et calcul-long, qui ne pose aucune limite, doit finir : par
# défaut, le temps de calcul est infini, comme sous Linux ; des signaux
# qu'un programme s'envoie (sig-term, sig-abort : terminés par leur
# action par défaut), un gestionnaire que le noyau n'appelle pas encore
# (sig-gestion, et sig-faute pour une faute : arrêtés, le message le dit,
# alors que Linux appelle le gestionnaire), SIGXCPU ignoré jusqu'à la
# limite dure (xcpu-ignore : SIGKILL) ; un futex attendu sans délai, que
# rien ne peut réveiller (futex-sans-fin : arrêté, le message le dit), un
# programme qui change de nom (PR_SET_NAME) puis fait une faute
# (nom-faute : le message porte le nouveau nom) ; puis des
# exécutables que le noyau doit refuser :
#   - wx : un segment W+X (ld -N) ;
#   - derniere-page : des segments dans les dernières pages de la moitié
#     basse (là où est la pile, et dans la page interdite) ;
#   - tronque : les 40 premiers octets d'un exécutable ;
# et un qu'il refusait jusqu'en 6b, et doit maintenant placer lui-même :
#   - et-dyn : un exécutable indépendant de la position, sans
#     interpréteur ni relocations (ld -pie --no-dynamic-linker).
# Puis des programmes dynamiques dont l'interpréteur (PT_INTERP) ne va
# pas, chacun refusé avec l'errno de Linux (TESTS_INTERP, ci-dessous) ;
# un seul doit tourner, interp-milieu (un zéro au milieu du chemin : Linux
# n'en lit que le début). Puis le lanceur (/etc/demarrage) : lecteur.wasm sans dossier pré-ouvert
# (il doit le dire) ; ses lignes refusées, chacune avec son numéro, sont
# en tête du fichier (voir tests-demarrage.txt). Enfin bonjour-asm, pour
# montrer que le noyau exécute encore des programmes après tout cela.
TESTS_LINUX = mmx-ecrit mmx-lit pointeurs tas mprotect ecrire-code executer-pile lire-noyau lire-zero hlt int80 icebp pas-a-pas mov-ss sgdt \
              zero grande-pile pile-executable recursion oom boucle brk-boucle calcul-long limite-egale \
              sig-term sig-abort sig-gestion sig-faute xcpu-ignore futex-sans-fin nom-faute \
              wx derniere-page et-dyn tronque bus-fichier faute-libc

$(LINUX)/tests/%.o: linux/tests/%.asm linux/tests/commun.inc
	mkdir -p $(LINUX)/tests
	nasm -f elf64 -i linux/tests/ $< -o $@

$(LINUX)/tests/%: $(LINUX)/tests/%.o
	ld -o $@ $<

# Les programmes de test écrits en C (sig-*, xcpu-ignore, futex-sans-fin,
# nom-faute), statiques
# comme bonjour-c. (Une règle explicite l'emporte : faute-libc et les
# interp-* ont la leur.)
$(LINUX)/tests/%: linux/tests/%.c
	mkdir -p $(LINUX)/tests
	gcc -static $(CFLAGS_LINUX) $< -o $@

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

# Un programme dynamique qui fait une faute dans la glibc partagée.
$(LINUX)/tests/faute-libc: linux/tests/faute-libc.c
	mkdir -p $(LINUX)/tests
	gcc $(CFLAGS_LINUX) $< -o $@

# Les programmes au mauvais interpréteur (6c). Les premiers, un programme C
# qui ne doit jamais tourner (linux/tests/interp.c), liés par gcc avec un
# autre interpréteur, rangé dans /interp de l'archive des tests :
#   - interp-absent : un chemin qui n'existe pas (ENOENT) ;
#   - interp-dossier : un dossier (EACCES) ;
#   - interp-non-exec : un fichier sans le droit d'exécution (EACCES) ;
#   - interp-pas-elf : 200 octets qui ne sont pas un ELF (ELIBBAD) ;
#   - interp-court : 8 octets, moins que l'en-tête ELF (EIO) ;
#   - interp-coupe : les 200 premiers octets de ld-linux, sa table des
#     en-têtes coupée (ELIBBAD) ;
#   - interp-core : ld-linux devenu un ET_CORE (refusé ; Linux le tuerait
#     par SIGSEGV après le point de non-retour) ;
#   - interp-objet : un fichier objet .o, ET_REL (ELIBBAD) ;
#   - interp-chevauche : un programme ET_EXEC à 0x400000 (gcc -no-pie)
#     dont l'interpréteur est bonjour-asm, un ET_EXEC aux mêmes adresses
#     (refusé ; Linux le poserait par-dessus le programme).
# Puis des ELF écrits à la main (linux/tests/interp.asm), pour ce que gcc
# ne sait pas produire : interp-sans-zero (ENOEXEC), interp-hors-fichier
# (EIO), et interp-milieu, qui doit tourner. Enfin interp-gros, qui doit
# tourner aussi : son interpréteur (linux/tests/interpreteur-gros.asm) a
# 48 en-têtes de programme, une table que le noyau copie dans un bloc de
# plus de 2 Kio, et qu'il doit rendre avant de compter la mémoire.
TESTS_INTERP = interp-absent interp-dossier interp-non-exec interp-pas-elf interp-court interp-coupe \
               interp-core interp-objet interp-chevauche interp-sans-zero interp-hors-fichier interp-milieu \
               interp-gros
INTERP_absent = /lib/absent
INTERP_dossier = /tmp
INTERP_non-exec = /etc/demarrage
INTERP_pas-elf = /interp/pas-elf
INTERP_court = /interp/court
INTERP_coupe = /interp/coupe
INTERP_core = /interp/core
INTERP_objet = /interp/objet
INTERP_gros = /interp/gros

$(addprefix $(LINUX)/tests/interp-,absent dossier non-exec pas-elf court coupe core objet gros): $(LINUX)/tests/interp-%: linux/tests/interp.c
	mkdir -p $(LINUX)/tests
	gcc $(CFLAGS_LINUX) -Wl,--dynamic-linker=$(INTERP_$*) $< -o $@

$(LINUX)/tests/interp-chevauche: linux/tests/interp.c
	mkdir -p $(LINUX)/tests
	gcc -no-pie $(CFLAGS_LINUX) -Wl,--dynamic-linker=/bin/bonjour-asm $< -o $@

$(LINUX)/tests/interp-sans-zero: linux/tests/interp.asm
	mkdir -p $(LINUX)/tests
	nasm -f bin -D SANS_ZERO $< -o $@

$(LINUX)/tests/interp-hors-fichier: linux/tests/interp.asm
	mkdir -p $(LINUX)/tests
	nasm -f bin -D HORS_FICHIER $< -o $@

$(LINUX)/tests/interp-milieu: linux/tests/interp.asm
	mkdir -p $(LINUX)/tests
	nasm -f bin -D MILIEU $< -o $@

# Les faux interpréteurs, rangés dans /interp de l'archive des tests.
INTERPRETEURS = $(addprefix $(LINUX)/tests/interpreteurs/,pas-elf court coupe core objet gros)

$(LINUX)/tests/interpreteurs/pas-elf:
	mkdir -p $(@D)
	head -c 200 /dev/zero | tr '\0' a > $@

$(LINUX)/tests/interpreteurs/court:
	mkdir -p $(@D)
	printf 'pas elf\n' > $@

$(LINUX)/tests/interpreteurs/coupe: $(GLIBC)/.copiee
	mkdir -p $(@D)
	head -c 200 $(GLIBC)/racine/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 > $@

# e_type, l'octet 16 de l'en-tête : 4, ET_CORE.
$(LINUX)/tests/interpreteurs/core: $(GLIBC)/.copiee
	mkdir -p $(@D)
	cp $(GLIBC)/racine/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 $@
	printf '\004' | dd of=$@ bs=1 seek=16 conv=notrunc status=none

$(LINUX)/tests/interpreteurs/objet: $(LINUX)/bonjour-asm.o
	mkdir -p $(@D)
	cp $< $@

$(LINUX)/tests/interpreteurs/gros: linux/tests/interpreteur-gros.asm
	mkdir -p $(@D)
	nasm -f bin $< -o $@

# La glibc partagée de la machine (6c) : ld-linux, et les bibliothèques
# que demandent nos programmes dynamiques, copiées dans glibc/racine aux
# chemins d'Ubuntu (/usr fusionné), avec un /etc/ld.so.cache fabriqué
# par ldconfig sur cette racine de préparation (-r : sans root ; -X : sans
# toucher aux liens des bibliothèques), et notre libessai.so dans
# /usr/local/lib, que le cache doit connaître aussi. Jamais commitées
# (.gitignore) : ce sont les fichiers de la machine qui construit, copiés
# de nouveau chaque fois que leur CONTENU change. Pas leur date : dpkg
# garde celle de la construction du paquet, et une glibc installée par apt
# après notre copie peut avoir une date plus ancienne qu'elle. D'où une
# empreinte (sha256) de tout ce qui entre dans la copie, recalculée à
# chaque construction (FORCE) et gardée dans .copiee : la copie n'est
# refaite, et .copiee touché, que si elle a changé. Deux vérifications
# avant de copier :
#   - le PT_INTERP de nos programmes (/lib64/ld-linux-x86-64.so.2) mène
#     bien, sur cette machine, au ld-linux qu'on copie ;
#   - ldconfig est de la même version de la glibc que lui (2.39) : le
#     format du cache en dépend. La version amont seulement, pas la
#     révision d'Ubuntu (2.39-0ubuntu8.9) : ldconfig est dans un autre
#     paquet (libc-bin), qu'une mise à jour de libc6 seule laisse à sa
#     révision, sans rien changer au format.
# (GLIBC, GLIBC_HOTE et GLIBC_FICHIERS sont définis plus haut, avec LINUX :
# make lit les prérequis d'une règle dès qu'il la rencontre.)
COPIE_GLIBC = $(addprefix $(GLIBC_HOTE)/,$(GLIBC_FICHIERS)) racine/etc/ld.so.conf $(LINUX)/libessai.so
$(GLIBC)/.copiee: $(LINUX)/libessai.so FORCE
	@empreinte=$$(sha256sum $(COPIE_GLIBC) | sha256sum | cut -d ' ' -f 1); \
	test "$$(cat $@ 2>/dev/null)" != "$$empreinte" || exit 0; \
	set -ex; \
	test "$$(readlink -f /lib64/ld-linux-x86-64.so.2)" = $(GLIBC_HOTE)/ld-linux-x86-64.so.2; \
	v1=$$(/sbin/ldconfig --version | sed -n '1s/.* \([0-9][0-9.]*[0-9]\)\.\{0,1\}$$/\1/p'); \
	v2=$$($(GLIBC_HOTE)/ld-linux-x86-64.so.2 --version | sed -n '1s/.* \([0-9][0-9.]*[0-9]\)\.\{0,1\}$$/\1/p'); \
	test -n "$$v1" && test "$$v1" = "$$v2" || { echo "ldconfig ($$v1) et ld-linux ($$v2) : deux glibc differentes"; exit 1; }; \
	rm -rf $(GLIBC); \
	mkdir -p $(GLIBC)/racine/usr/lib/x86_64-linux-gnu $(GLIBC)/racine/usr/local/lib $(GLIBC)/racine/etc; \
	cp $(addprefix $(GLIBC_HOTE)/,$(GLIBC_FICHIERS)) $(GLIBC)/racine/usr/lib/x86_64-linux-gnu/; \
	cp $(LINUX)/libessai.so $(GLIBC)/racine/usr/local/lib/; \
	ln -s usr/lib $(GLIBC)/racine/lib; \
	cp racine/etc/ld.so.conf $(GLIBC)/racine/etc/; \
	/sbin/ldconfig -X -r $(GLIBC)/racine -C /etc/ld.so.cache -f /etc/ld.so.conf; \
	echo "$$empreinte" > $@

# L'archive des programmes de test : sa description est fabriquée ici, une
# ligne par programme (voir archive.sh), avec son /etc/demarrage
# (tests-demarrage.txt), qui les lance l'un après l'autre.
LECTEUR = lecteur/target/wasm32-unknown-unknown/release/lecteur.wasm
tests.cpio: archive.sh tests-demarrage.txt $(addprefix $(LINUX)/tests/,$(TESTS_LINUX) $(TESTS_INTERP)) $(INTERPRETEURS) \
            $(LINUX)/bonjour-asm $(GLIBC)/.copiee FORCE
	cd lecteur && cargo build --release
	{ echo "dir /bin 755 0 0"; \
	  for p in $(TESTS_LINUX) $(TESTS_INTERP); do echo "file /bin/$$p $(LINUX)/tests/$$p 755 0 0"; done; \
	  echo "file /bin/lecteur.wasm $(LECTEUR) 755 0 0"; \
	  echo "file /bin/bonjour-asm $(LINUX)/bonjour-asm 755 0 0"; \
	  echo "dir /etc 755 0 0"; \
	  echo "file /etc/demarrage tests-demarrage.txt 644 0 0"; \
	  echo "file /etc/ld.so.conf racine/etc/ld.so.conf 644 0 0"; \
	  echo "file /etc/ld.so.cache $(GLIBC)/racine/etc/ld.so.cache 644 0 0"; \
	  echo "dir /tmp 1777 0 0"; \
	  echo "dir /interp 755 0 0"; \
	  for i in $(INTERPRETEURS); do echo "file /interp/$${i##*/} $$i 755 0 0"; done; \
	  echo "dir /usr 755 0 0"; \
	  echo "dir /usr/lib 755 0 0"; \
	  echo "dir /usr/lib/x86_64-linux-gnu 755 0 0"; \
	  for f in $(GLIBC_FICHIERS); do echo "file /usr/lib/x86_64-linux-gnu/$$f $(GLIBC)/racine/usr/lib/x86_64-linux-gnu/$$f 755 0 0"; done; \
	  echo "dir /usr/lib64 755 0 0"; \
	  echo "slink /usr/lib64/ld-linux-x86-64.so.2 ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 777 0 0"; \
	  echo "slink /lib usr/lib 777 0 0"; \
	  echo "slink /lib64 usr/lib64 777 0 0"; } | sh archive.sh $@ -

# Le /etc/demarrage des tests : d'abord les lignes que le lanceur doit
# refuser, chacune à un numéro qui ne bouge pas quand on ajoute des
# programmes (ligne 2 : un guillemet non fermé ; 3 : --dir= devant un
# programme Linux ; 4 : un chemin relatif ; 5 : un programme absent ; 6 :
# un dossier ; 7 : une barre finale après un fichier ; 8 : un fichier sans
# le droit d'exécution) ; puis chaque programme de TESTS_LINUX et de
# TESTS_INTERP, lecteur.wasm sans dossier pré-ouvert, et bonjour-asm.
tests-demarrage.txt: Makefile
	{ echo "# Fabrique par le Makefile (tests.cpio)."; \
	  echo "/bin/bonjour-asm \"pas ferme"; \
	  echo "--dir=/ /bin/bonjour-asm"; \
	  echo "bin/bonjour-asm"; \
	  echo "/bin/absent"; \
	  echo "/bin"; \
	  echo "/bin/bonjour-asm/"; \
	  echo "/etc/demarrage"; \
	  for p in $(TESTS_LINUX) $(TESTS_INTERP); do echo "/bin/$$p"; done; \
	  echo "/bin/lecteur.wasm"; \
	  echo "/bin/bonjour-asm"; } > $@

PROGRAMMES_HOTE = $(addprefix $(LINUX)/,bonjour-asm bonjour-asm.o bonjour-asm-wx bonjour-asm-pile-executable bonjour-c bonjour-c-deux-segments bonjour-c-pie bonjour-c-dynamique)

# L'archive de démarrage, décrite par archive.txt : le noyau la déballe,
# puis lance ce que dit son /etc/demarrage (voir archive.sh).
programmes.cpio: archive.sh archive.txt racine/etc/bonjour.txt racine/etc/demarrage racine/etc/ld.so.conf $(GLIBC)/.copiee $(LINUX)/bonjour-asm $(LINUX)/pile $(LINUX)/sse $(LINUX)/bonjour-c $(LINUX)/bonjour-c-pie $(LINUX)/bonjour-c-dynamique $(LINUX)/dynamique $(LINUX)/libessai.so $(LINUX)/memoire $(LINUX)/claude-version $(LINUX)/temps $(LINUX)/fichiers $(LINUX)/arbre $(LINUX)/segments $(LINUX)/signaux $(LINUX)/systeme FORCE
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
# secteur par secteur, et l'archive porte la glibc depuis 6c : de 1,3 à
# 3,8 s mesurées ici sur une machine tranquille, contre 2,5 s en 6b ; mais
# jusqu'à 14,6 s quand trois relectures se partageaient les 12 cœurs de la
# machine, d'où la marge). verifier.sh le demande par `make duree` ; ne
# pas le lancer sur une machine saturée.
DUREE = 12

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

tests-hote: $(SUITE)/.convertie $(PROGRAMMES_HOTE) $(LINUX)/memoire $(LINUX)/claude-version $(LINUX)/temps $(LINUX)/fichiers $(LINUX)/segments $(LINUX)/dynamique $(LINUX)/libessai.so \
            $(LINUX)/signaux $(LINUX)/systeme
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
	LD_LIBRARY_PATH=$(LINUX) ./$(LINUX)/dynamique | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/signaux | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/systeme | tee /dev/stderr | (! grep -q ECHEC)

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
	-timeout $(DUREE) qemu-system-x86_64 -display none -no-reboot -drive format=raw,file=test-trace.bin -serial file:trace.log
	@echo "--- dans notre noyau ---"
	@sed -n '/bonjour-c-dynam : programme/,/bonjour-c-dynam : termine/p' trace.log | grep -E '^\[(trace|linux)\]|bonjour-c-dynam :'
	@echo "--- sous Linux, sur l'hote (strace) ---"
	@strace ./$(LINUX)/bonjour-c-dynamique 2>&1 >/dev/null | grep -v "^execve"

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
	rm -f boot*.bin test-*.bin programmes.cpio tests.cpio tests-demarrage.txt serial.log trace.log qemu.log ecran.png test-*.log
	rm -rf $(LINUX)
	rm -rf $(GLIBC)
	rm -rf $(SUITE)
	cd noyau && cargo clean
	cd wasm && cargo clean
	cd bonjour && cargo clean
	cd lecteur && cargo clean
	cd formats && cargo clean
	cd zones && cargo clean
	cd fichiers && cargo clean

.PHONY: run texte test duree debug capture gdb dump trace tests-hote tests-qemu suite clean FORCE
