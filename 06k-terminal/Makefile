# Sous-étape 6k : le terminal (à venir). D'abord, les soldes des étapes
# passées, chacun dans un commit « Reste de » : les tests sur l'hôte, stricts
# sous le Linux de référence (linux/tcp.c, unix.c, proprietaire.c,
# copies.c, fichiers.c ; .devcontainer/linux-de-reference.sh) ; la glibc
# de l'image figée (GLIBC_VERSION, $(GLIBC_PAQUETS)/.extraits).
# De 6j : le multiprocesseur. Une zone par processeur trouvée par
# le segment GS (noyau/src/processeur.rs), `swapgs` à chaque entrée dans le
# noyau et à chaque sortie (appel_systeme.rs, interruptions.rs : les trois
# chemins de Linux, dont le « paranoïaque » des vecteurs à pile IST), la
# TSS et la GDT de chaque processeur (gdt.rs) ; getcpu.
# De 6i : la première réponse de Claude. Les statistiques des verrous
# (make verrous), le verrou qui dort en lecture et en écriture
# (noyau/src/attente.rs, VerrouLE) et la mémoire du processus sous lui
# (processus.rs, memoire.rs : le mmap_lock de Linux), les redirections,
# cd et les groupes de /etc/demarrage (formats/src/commande.rs,
# noyau/src/programmes.rs), fadvise64, copy_file_range et sendfile
# (appels_fichiers.rs, tube.rs), inotify (surveillance.rs), la fausse API
# que sert QEMU (outils/serveur-http, outils/fausse-api.sse) et le jeton
# de l'abonnement (outils/jeton-claude, make jeton, make claude-bonjour).
# De 6h : le générateur aléatoire de Linux, TCP, AF_UNIX. La
# bibliothèque crypto/ (ChaCha20, BLAKE2s, SipHash), rejouée par le noyau
# au démarrage ; le générateur de Linux (crypto/src/alea.rs et
# noyau/src/aleatoire.rs : le réservoir, RDSEED et RDRAND, les
# interruptions, la gigue ; getrandom, /dev/random, linux/aleatoire.c),
# et virtio-rng, le générateur matériel de QEMU (noyau/src/virtio_rng.rs) ;
# les échéances du réseau (inet/src/echeances.rs, et la roue de Linux : roue/), le contexte réseau
# (noyau/src/reseau/contexte.rs) et la fermeture différée des sockets ;
# TCP (inet/src/tcp.rs, la machine à états, et inet/src/ports_tcp.rs ;
# noyau/src/reseau/tcp.rs, et la possession d'une socket dans
# noyau/src/attente.rs ; linux/tcp.c), jusqu'à l'API pour claude -p.
# De 6g : le réseau. Le bus PCI (formats/src/pci.rs et
# noyau/src/pci.rs), les vecteurs d'interruption à la demande et MSI-X,
# virtio (noyau/src/virtio.rs, virtqueue.rs) et la carte virtio-net, ses
# files et la tâche du réseau (noyau/src/reseau/) ; Ethernet, IPv4 et la
# configuration par DHCP (formats/src/reseau/, et la bibliothèque inet/ :
# les routes, le client DHCP), ARP et la table des voisins ; les sockets
# et UDP, avec l'interface de boucle lo ; ICMP et les sockets de ping ; le
# DNS, par la glibc (linux/dns.c).
# De 6f : les signaux livrés à leurs gestionnaires (le
# cadre de signal, rt_sigreturn, la reprise des appels interrompus),
# l'attente d'événements (poll, select, epoll), les tubes, /proc fabriqué
# à la demande, et claude -p, qui va jusqu'à essayer le réseau. De 6e :
# l'ordonnanceur, l'APIC et les fils (ACPI, l'APIC local et l'IO-APIC, le
# TSC, une pile noyau par tâche, EEVDF, clone et futex). De 6d : claude
# --version, le vrai binaire de Claude Code, RLIMIT_CPU, les signaux
# enregistrés, /proc et /sys (fichiers/src/noyaufs.rs). Le reste
# vient de 6c (les programmes dynamiques : ld-linux et la glibc
# partagée, le lanceur /etc/demarrage), de 6b (le système de fichiers en
# mémoire, fichiers/, et les fichiers projetés), de 6a (la mémoire
# virtuelle à la demande, zones/) et de l'étape 5 : le noyau (noyau/)
# exécute des binaires Linux et garde l'interpréteur WebAssembly de
# l'étape 4 (wasm/) ; il est lancé par notre chargeur (boot.asm), qui le
# lit par morceaux, en mode irréel.
#   make        -> vérifie les règles du noyau (cargo clippy : aucune
#                  allocation qui panique, noyau/clippy.toml), compile le
#                  noyau et les programmes, fabrique l'archive, assemble
#                  le chargeur, colle les trois dans boot.bin
#   make run    -> démarre dans QEMU avec une fenêtre (port série dans le terminal)
#   make texte  -> même chose, mais l'écran VGA s'affiche dans le terminal
#                  (pratique dans un conteneur sans fenêtre ; quitter : Echap puis 2, puis « quit »)
#   make test   -> démarre sans écran (DUREE secondes), puis affiche serial.log
#   make duree  -> le temps qu'il faut laisser au démarrage (pour verifier.sh),
#                  et make qemu-disque, make qemu-options : la machine
#                  (un disque virtio, un processeur Nehalem, 2 Gio)
#   make debug  -> sans écran, journalise exceptions et reset du CPU dans qemu.log
#   make capture -> démarre sans écran, et enregistre l'écran dans ecran.png
#                  une fois claude terminé
#   make gdb    -> QEMU figé au démarrage, en attente de GDB sur le port 1234
#   make dump   -> affiche l'image octet par octet
#   make trace  -> démarre un noyau qui affiche chaque appel système des
#                  programmes Linux (comme strace), puis montre ceux de
#                  claude --version, et leurs noms sous Linux, sur l'hôte,
#                  avec strace, pour comparer
#   make verrous -> démarre un noyau qui mesure combien de temps chaque
#                  endroit qui prend un verrou garde les interruptions
#                  coupées, et l'affiche après chaque programme (6i)
#   make tests-qemu -> les scénarios dans QEMU : un noyau qui déborde exprès
#                  de sa pile doit le dire (page de garde, double faute) ;
#                  un noyau gonflé au-delà de 1 Mio doit être lu en entier ;
#                  une carte derrière un pont PCI doit être trouvée ;
#                  une carte sans MSI-X laissée éteinte ; le câble
#                  débranché puis rebranché, vu ; un réseau sans DHCP ;
#                  et make claude-p
#   make claude-p -> le jalon de 6f à 6i, dans une image à part :
#                  claude -p bonjour jusqu'à l'API (6h : TLS par Bun
#                  sur notre TCP, et la réponse de l'API à une fausse clé),
#                  puis sa réponse, venue d'une fausse API que sert QEMU
#                  (6i : outils/serveur-http) (claude-p-attendu.txt)
#   make jeton  -> enregistre le jeton de l'abonnement de David, celui de
#                  `claude setup-token`, dans ~/.config/claude-os/jeton
#                  (outils/jeton-claude) : sur sa machine seulement
#   make claude-bonjour -> le jalon de 6i : la réponse de Claude à
#                  « bonjour », par la vraie API, avec ce jeton ; jamais
#                  dans la CI
#   make tests-hote -> les tests sur la machine hôte : ceux de la
#                  bibliothèque des formats (formats/ : archive cpio,
#                  exécutables ELF, essayés aussi sur de vrais programmes
#                  Linux, dont un gcc -static) ; ceux de la carte des zones
#                  (zones/ : des cas écrits à la main, puis des milliers
#                  d'opérations au hasard comparées à un modèle) ; ceux du
#                  système de fichiers (fichiers/ : une règle de Linux par
#                  cas, puis des milliers d'opérations au hasard comparées
#                  à un modèle naïf) ; ceux de la pile d'IPv4 (inet/ :
#                  les routes, le client DHCP, les échéances, TCP et ses
#                  ports, à l'horloge simulée) ; ceux
#                  de la bibliothèque crypto (crypto/ : ChaCha20, BLAKE2s
#                  et SipHash, contre les vecteurs officiels, et les règles
#                  du générateur de Linux) ; puis
#                  pour l'interpréteur WebAssembly, télécharge et
#                  convertit la suite de tests officielle si besoin, puis la
#                  rejoue contre la bibliothèque (tableau par fichier) ;
#                  vérifie aussi que les six bibliothèques se compilent
#                  pour le noyau (no_std), sans avertissement ; enfin
#                  lance linux/memoire sur l'hôte : nos codes d'erreur de
#                  mmap & co. doivent être ceux du vrai Linux ; et
#                  linux/claude-version, qui doit y réussir aussi, comme
#                  linux/temps (les horloges) et linux/fichiers (nos codes
#                  d'erreur des fichiers doivent être ceux de Linux), et
#                  linux/dynamique (ld-linux, la glibc partagée, dlopen),
#                  linux/signaux (nos codes d'erreur des signaux),
#                  linux/systeme (uname, futex, prctl...),
#                  linux/processeurs (sched_setaffinity, getcpu, 6j),
#                  linux/evenements (eventfd, epoll), linux/proc,
#                  linux/clone (clone, clone3), linux/fils et
#                  linux/courses (des programmes à plusieurs fils),
#                  linux/reseau (les sockets UDP et ICMP, sur lo) et
#                  linux/dns (getaddrinfo, par un DNS du programme),
#                  linux/aleatoire (getrandom, /dev/random),
#                  linux/tcp (les sockets TCP, sur lo) et
#                  linux/unix (les sockets AF_UNIX),
#                  linux/proprietaire (F_SETOWN, SIGURG, O_ASYNC),
#                  linux/autocode (du code qui se modifie, à cheval sur deux pages)
#   make suite  -> seulement télécharger et convertir la suite
#   make clean  -> supprime les fichiers générés, la suite, wabt et la compilation
#
# L'image disque : secteur 0 = 1er étage, puis le 2e étage, puis le noyau,
# puis l'archive de programmes, chacun complété au secteur.

# La machine de l'étape : `claude` demande un processeur qui a SSE4.2 et
# POPCNT (qemu64 n'en a pas : SIGILL, mesuré en 6a ; Nehalem suffit, sans
# AVX) et de la mémoire (le tmpfs a droit à la moitié de la machine, et
# claude pèse 291 Mo : 1 Gio suffit, mesuré, 2 laissent de la marge). Le
# disque en virtio : le BIOS de QEMU lit un disque IDE mot par mot, 74 s
# pour les 307 Mo de l'archive, contre 3,8 s en virtio (mesuré sur une
# machine tranquille, du lancement de QEMU à la dernière ligne du
# chargeur) ; le chargeur (int 0x13) ne change pas. verifier.sh les demande par
# `make qemu-disque` et `make qemu-options`.
#
# La carte réseau (6g) : virtio-net, sur le réseau « utilisateur » de QEMU
# (slirp : 10.0.2.0/24, la passerelle 10.0.2.2, son DNS 10.0.2.3). Chaque
# machine de l'étape la nomme, celles de tests-qemu comprises : sans
# option de réseau, QEMU ajoute d'office une Intel e1000 (mesuré). Et par
# -netdev et -device : la forme courte -nic user,model=virtio-net-pci donne
# une carte sans MSI-X (vectors = 0, mesuré avec QEMU 8.2).
# Et un serveur HTTP (6h) : chaque connexion du système invité vers
# 10.0.2.100:80 est servie par outils/serveur-http, que QEMU lance sur
# l'hôte (guestfwd, cmd:), sans port ouvert sur l'hôte ni Internet ; par son
# chemin absolu, QEMU pouvant être lancé d'ailleurs (verifier.sh, depuis la
# racine du dépôt). Sans virgule ni espace dans le chemin du dépôt (la
# syntaxe de -netdev).
QEMU_DISQUE = virtio
QEMU_RESEAU = -netdev user,id=n0,guestfwd=tcp:10.0.2.100:80-cmd:$(CURDIR)/outils/serveur-http -device virtio-net-pci,netdev=n0
#
# Le générateur matériel (6h) : virtio-rng, l'aléa de l'hôte, comme Linux
# l'emploie dans une machine virtuelle ; sans lui, et sans RDRAND (Nehalem
# n'en a pas), le générateur du noyau attend la gigue. Chaque machine de
# l'étape l'a, sauf celle des programmes de test (QEMU_PROGRAMMES) : avec
# -cpu qemu64, elle passe par la gigue, le chemin de la machine sans
# générateur.
QEMU_ALEA = -device virtio-rng-pci
#
# Les processeurs (6j) : quatre, comme la machine de la CI (4 vCPU). Le
# noyau démarre les secondaires par INIT-SIPI-SIPI (noyau/src/smp.rs) ;
# chaque machine de l'étape en a quatre, celles de tests-qemu comprises,
# sauf le scénario « -smp 1 » qui vérifie le chemin d'un seul processeur.
QEMU_SMP = -smp 4
QEMU_OPTIONS = -cpu Nehalem -m 2G $(QEMU_SMP) $(QEMU_RESEAU) $(QEMU_ALEA)
QEMU = qemu-system-x86_64 -drive format=raw,file=boot.bin,if=$(QEMU_DISQUE) $(QEMU_OPTIONS)
MON  = /tmp/qemu-mon-os.sock
NOYAU_ELF = noyau/target/x86_64-unknown-none/release/noyau
# Le programme WebAssembly de l'archive (bonjour/, compilé par rustc pour
# la cible wasm32-unknown-unknown).
BONJOUR = bonjour/target/wasm32-unknown-unknown/release/bonjour.wasm

# Assemble une image disque : $(call image,ELF du noyau,archive,NOM) écrit
# NOM.bin, en passant par NOM-noyau.bin et NOM-chargeur.bin ; l'archive y
# est recopiée directement, au bout.
#   - objcopy -O binary retire les en-têtes ELF du noyau et ne garde que
#     les octets à recopier en mémoire, à partir de 1 Mio ; truncate
#     complète au secteur ;
#   - le chargeur doit savoir combien de secteurs lire (NOYAU_SECTEURS),
#     où s'arrête le noyau en mémoire une fois sa .bss et ses piles
#     comptées (NOYAU_MEMOIRE, l'adresse du symbole __bss_fin de
#     linker.ld, moins celle du début du noyau), et la taille de
#     l'archive (ARCHIVE_OCTETS). Si nm ne trouve pas __bss_fin (le
#     symbole renommé, un noyau dépouillé), on s'arrête : bash calculerait
#     sans broncher 0x - 0xffffffff80100000, près de 2 Gio ;
#   - l'archive va telle quelle au bout de l'image, complétée au secteur
#     sur l'image elle-même : pas de copie intermédiaire (300 Mo de plus
#     par image, depuis que l'archive porte claude).
define image
	objcopy -O binary $(1) $(3)-noyau.bin
	truncate -s %512 $(3)-noyau.bin
	fin=$$(nm -P $(1) | awk '$$1 == "__bss_fin" { print $$3 }'); \
	test -n "$$fin" || { echo "__bss_fin introuvable dans $(1)"; exit 1; }; \
	nasm -f bin \
	  -D NOYAU_SECTEURS=$$(( $$(stat -c %s $(3)-noyau.bin) / 512 )) \
	  -D NOYAU_MEMOIRE=$$(( 0x$$fin - 0xffffffff80100000 )) \
	  -D ARCHIVE_OCTETS=$$(stat -c %s $(2)) \
	  boot.asm -o $(3)-chargeur.bin
	cat $(3)-chargeur.bin $(3)-noyau.bin $(2) > $(3).bin
	truncate -s %512 $(3).bin
endef

# cargo décide lui-même s'il faut recompiler : on l'appelle à chaque fois.
# D'abord les règles du noyau (6h) : cargo clippy, sur toutes ses variantes
# (les fonctionnalités des noyaux de test comprises) ; une règle enfreinte
# est une erreur, et arrête make.
boot.bin: programmes.cpio FORCE
	cd noyau && cargo clippy --release --all-features
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
#     rt_sigprocmask, sigaltstack, kill...) et leur file (siginfo,
#     rt_sigqueueinfo, rt_sigtimedwait) contre ce qu'en fait Linux ; sur
#     l'hôte aussi ;
#   - gestionnaires : gcc -static, les gestionnaires de signaux (le cadre de
#     signal, rt_sigreturn, la pile de secours, les drapeaux, l'ordre, les
#     fautes) ; sur l'hôte aussi, et dans l'archive des tests (qemu64 et
#     -cpu max : avec et sans XSAVE) ;
#   - reprise : gcc -static, les appels interrompus par un gestionnaire
#     (EINTR, ou repris : SA_RESTART, restart_syscall ; rt_sigsuspend,
#     pause, le masque rendu) ; sur l'hôte aussi ;
#   - suspendre : gcc -static, des fils suspendus et relancés par SIGPWR,
#     comme le fait JavaScriptCore (sigsuspend dans le gestionnaire) ; sur
#     l'hôte aussi ;
#   - attente : gcc -static, attendre plusieurs fichiers à la fois (poll,
#     ppoll, select, pselect6, epoll : le sondage de chaque sorte, les
#     délais, les masques, les réveils par un autre fil) ; sur l'hôte aussi ;
#   - tubes : gcc -static, les tubes (pipe2, les pages et la fusion, la
#     capacité, la fin, SIGPIPE, les paquets, 10 Mo entre deux fils) ; sur
#     l'hôte aussi ; `tubes sigpipe` meurt de SIGPIPE (code 141) ;
#   - systeme : gcc -static, les petits appels de claude (uname,
#     sched_getaffinity, futex, prctl) ; sur l'hôte aussi ;
#   - processeurs : gcc -static, ce qu'un programme voit des processeurs
#     (6j) : cpu/online et get_nprocs, sched_getaffinity, sched_setaffinity
#     et ses refus, getcpu, des fils épinglés qui restent chacun sur son
#     processeur ; sur l'hôte aussi ;
#   - evenements : gcc -static, eventfd et epoll ; sur l'hôte aussi ;
#   - proc : gcc -static, /proc (maps, statm, exe, /proc/sys) et /sys
#     (cpu/online, transparent_hugepage) ; sur l'hôte aussi ;
#   - ajout : gcc -static, deux programmes qui ajoutent au même fichier
#     (O_APPEND), un troisième qui vérifie ; sur l'hôte aussi ;
#   - clone : gcc -static, les refus de clone et clone3, et un fil créé par
#     l'appel brut ; sur l'hôte aussi ;
#   - fils : gcc -static, des fils par la glibc (verrous, conditions,
#     __thread, un verrou robuste, l'arrondi et les masques hérités ; le
#     processus finit avec son dernier fil, ou avec le groupe) ; sur l'hôte
#     aussi ;
#   - courses : gcc -static, quatre fils qui ferment, changent de dossier et
#     se servent en même temps des mêmes descripteurs ; sur l'hôte aussi ;
#   - redirections : gcc -static, lancé avec `< f` et `3< g` (6i) : ses
#     descripteurs 0 et 3 sont ces fichiers, et /proc/self/fd/3 d'un
#     fichier sans droits rend EACCES, le descripteur restant lisible ; sur
#     l'hôte aussi ;
#   - surveillance : gcc -static, inotify (6i) : chaque événement de Linux,
#     dans son ordre, et les refus de ses appels ; sur l'hôte aussi, dans
#     /dev/shm (un tmpfs, comme notre /tmp) ;
#   - copies : gcc -static, copy_file_range, sendfile et fadvise64 (6i),
#     leurs transferts et leurs refus, ceux de Linux, pour chaque sorte de
#     fichier ; sur l'hôte aussi, dans /dev/shm (un tmpfs, comme notre /tmp :
#     les positions extrêmes dépendent du système de fichiers) ;
#   - effacer : gcc -static, efface comme `rm -rf` (6i), ou seulement le
#     contenu d'un dossier, ou en crée un pour l'essayer : ce qu'un groupe
#     de /etc/demarrage a laissé, pour qu'il rende toute sa mémoire ; sur
#     l'hôte aussi ;
#   - dossier : gcc -static, son dossier courant, PWD et OLDPWD, après un
#     `cd` de /etc/demarrage (6i) ; sur l'hôte, la même suite de `cd`,
#     jouée par dash (/bin/sh), sans environnement, doit donner ce que
#     /etc/demarrage attend ;
#   - fautes : gcc -static, la mémoire disputée par ses fils (6i) : quatre
#     qui fautent pendant qu'un autre rend des pages et qu'un autre projette,
#     protège et retire des zones, la pile qui grandit ; puis exit_group au
#     milieu de tout cela (sous trois noms, fautes-fin-1 à 3, des liens
#     physiques : chaque fin se vérifie à part) ; sur l'hôte aussi ;
#   - troncature : gcc -static, des fautes de page sur un fichier projeté
#     pendant qu'un autre fil le raccourcit (6i) : la première lecture, ou
#     la copie à l'écriture ; aucune page relue au-delà de la fin ; sur
#     l'hôte aussi, dans /dev/shm ;
#   - reseau : gcc -static, les sockets UDP et ICMP sur lo (les appels et
#     leurs refus, les options, la socket vue comme fichier, les attentes
#     d'un fil à l'autre, 10 000 allers-retours, les erreurs ICMP, le ping) ;
#     sur l'hôte aussi ;
#   - dns : gcc sans option (la glibc partagée, comme claude), getaddrinfo
#     par un serveur DNS du programme (des réponses de travers, NXDOMAIN,
#     /etc/hosts) ; sur l'hôte aussi ;
#   - tcp : gcc -static, les sockets TCP sur lo (les appels et leurs refus,
#     les options, l'écoute et sa file, les fermetures, epoll par front,
#     1 Mio en aller-retour entre deux fils) ; sur l'hôte aussi ;
#   - unix : gcc -static, les sockets AF_UNIX (les trois sortes, les noms,
#     les connexions et leurs fermetures, socketpair, /proc/net/unix, un
#     serveur et trois clients en fils) ; sur l'hôte aussi ;
#   - client-tcp : gcc -static, le client du serveur WebAssembly
#     bonjour-tcp.wasm (deux lignes envoyées, rendues à l'envers) ; dans
#     notre noyau seulement (son serveur est un programme WebAssembly) ;
#   - telecharger : gcc sans option (getaddrinfo, comme claude), une page
#     HTTP de 4 Mio que sert QEMU (outils/serveur-http, par guestfwd),
#     vérifiée octet par octet ; dans notre noyau seulement ;
#   - aleatoire : gcc -static, le générateur (getrandom et ses refus,
#     /dev/random, /dev/urandom, /proc/sys/kernel/random) ; sur l'hôte
#     aussi ;
#   - passerelle : gcc sans option, le réseau que le DHCP du démarrage a
#     configuré (/proc/net, le DNS de /etc/resolv.conf, un datagramme qui
#     part par eth0, le ping de la passerelle, api.anthropic.com) ; dans
#     notre noyau seulement (il connaît les adresses du réseau de QEMU) ;
#     `passerelle muet` dans le noyau des tests, `passerelle sans-reseau`
#     sur une machine sans carte (make tests-qemu).
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
# La glibc partagée de l'image, copiée dans glibc/ (voir $(GLIBC)/.copiee) :
# celle d'Ubuntu 24.04, à une révision figée, téléchargée et vérifiée (voir
# $(GLIBC_PAQUETS)/.extraits).
GLIBC_VERSION = 2.39-0ubuntu8.9
GLIBC_ADRESSE = https://launchpad.net/ubuntu/+archive/primary/+files
GLIBC_SHA256_LIBC6 = ff5557d99b51f761c4b7c92368b9cc45565eda17df9bf9eb4b134d09825008be
GLIBC_SHA256_LIBC_BIN = 066398a06ef1a218d4109461d4c636eafe83322ad19b179de9ef7af42b3fec58
GLIBC_PAQUETS = $(HOME)/.cache/claude-os/glibc-$(GLIBC_VERSION)
GLIBC_SOURCE = $(GLIBC_PAQUETS)/racine/usr/lib/x86_64-linux-gnu
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

$(LINUX)/gestionnaires: linux/gestionnaires.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/reprise: linux/reprise.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/suspendre: linux/suspendre.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/attente: linux/attente.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/tubes: linux/tubes.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/systeme: linux/systeme.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/processeurs: linux/processeurs.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/clone: linux/clone.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/fils: linux/fils.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@ -lm

$(LINUX)/courses: linux/courses.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/fautes: linux/fautes.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/troncature: linux/troncature.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/redirections: linux/redirections.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/dossier: linux/dossier.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/effacer: linux/effacer.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/copies: linux/copies.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/surveillance: linux/surveillance.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/reseau: linux/reseau.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/dns: linux/dns.c
	mkdir -p $(LINUX)
	gcc $(CFLAGS_LINUX) $< -o $@

$(LINUX)/tcp: linux/tcp.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/unix: linux/unix.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/proprietaire: linux/proprietaire.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/autocode: linux/autocode.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/client-tcp: linux/client-tcp.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/telecharger: linux/telecharger.c
	mkdir -p $(LINUX)
	gcc $(CFLAGS_LINUX) $< -o $@

$(LINUX)/aleatoire: linux/aleatoire.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/pmtu: linux/pmtu.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/options-ip: linux/options-ip.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/passerelle: linux/passerelle.c
	mkdir -p $(LINUX)
	gcc $(CFLAGS_LINUX) $< -o $@

$(LINUX)/evenements: linux/evenements.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/proc: linux/proc.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

# Deux programmes à la fois (6e) : lancés par `&` dans /etc/demarrage.
$(LINUX)/partage: linux/partage.c
	mkdir -p $(LINUX)
	gcc -static $(CFLAGS_LINUX) $< -o $@

$(LINUX)/ajout: linux/ajout.c
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
# action par défaut), un gestionnaire appelé (sig-gestion : le programme
# continue), un gestionnaire de faute (sig-faute : il est appelé, et sort
# avec 0), une faute dans le gestionnaire de la même faute (sig-refaute :
# tué), des
# cadres de signal impossibles (sig-restorer : sans adresse de
# retour ; sig-pile-perdue : un RSP où rien n'est projeté ;
# sig-secours : une pile de secours trop petite pour deux cadres) et
# un contexte refusé au retour (sig-mxcsr : un MXCSR invalide), des
# contextes que iretq refuse (sig-retour-cs, sig-retour-ss, sig-retour-rip :
# le « bad iret »), chacun tué par SIGSEGV comme sous Linux, le noyau
# continuant, SIGXCPU ignoré jusqu'à la
# limite dure (xcpu-ignore : SIGKILL) ; un futex attendu sans délai, que
# rien ne peut réveiller (futex-sans-fin : arrêté, le message le dit), de
# même un eventfd vide lu en bloquant (eventfd-bloque), un
# programme qui change de nom (PR_SET_NAME) puis fait une faute
# (nom-faute : le message porte le nouveau nom), un programme qui dort
# (dort : une touche tapée pendant son sommeil est affichée avant son
# réveil, voir tests-qemu) ; puis des
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
# Des programmes de test lancés ensemble par `&` (6e), avec leurs
# arguments, après les autres : deux qui écrivent 200 lignes longues sur la
# console (lignes : make tests-qemu compte les lignes entières de chacun),
# une cible qui dort 10 s et un programme qui lui envoie SIGTERM
# (signaler), qui doit la réveiller ; deux qui remplissent leurs registres
# vectoriels (YMM avec AVX, XMM sinon), MXCSR et x87, se préemptent, et
# doivent les retrouver intacts (avx) ; et, quand la mémoire manque, un
# gros qui la tient (oom-gros) et un petit qui en demande plus qu'il n'en
# reste (oom-petit) : le tueur OOM doit choisir le gros, et laisser finir le
# petit (les soldes d'avant 6k).
TESTS_PARALLELES = lignes cible signaler avx oom-gros oom-petit
TESTS_LINUX = mmx-ecrit mmx-lit pointeurs tas mprotect ecrire-code executer-pile lire-noyau lire-zero hlt int80 icebp pas-a-pas mov-ss sgdt \
              zero grande-pile pile-executable recursion oom boucle brk-boucle calcul-long limite-egale \
              sig-term sig-abort sig-gestion sig-faute sig-refaute sig-restorer sig-pile-perdue sig-mxcsr sig-secours \
              sig-retour-cs sig-retour-ss sig-retour-rip \
              xcpu-ignore futex-sans-fin nom-faute eventfd-bloque \
              wx derniere-page et-dyn tronque bus-fichier faute-libc dort

$(LINUX)/tests/%.o: linux/tests/%.asm linux/tests/commun.inc
	mkdir -p $(LINUX)/tests
	nasm -f elf64 -i linux/tests/ $< -o $@

$(LINUX)/tests/%: $(LINUX)/tests/%.o
	ld -o $@ $<

# Les programmes de test écrits en C (sig-*, xcpu-ignore, futex-sans-fin,
# nom-faute, eventfd-bloque), statiques
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

# La glibc partagée de l'image (6c) : ld-linux, et les bibliothèques que
# demandent nos programmes dynamiques, copiées dans glibc/racine aux chemins
# d'Ubuntu (/usr fusionné), avec un /etc/ld.so.cache fabriqué par ldconfig
# sur cette racine de préparation (-r : sans root ; -X : sans toucher aux
# liens des bibliothèques), et notre libessai.so dans /usr/local/lib, que le
# cache doit connaître aussi. Jamais commitées (.gitignore) : des binaires
# que nous n'avons pas écrits.
#
# D'où elles viennent (choix de conception, les soldes d'avant 6k) : des
# paquets d'Ubuntu 24.04 à une révision figée (libc6 et libc-bin,
# GLIBC_VERSION), téléchargés depuis Launchpad, qui garde chaque version
# publiée, et vérifiés par leur SHA-256, comme claude, wabt et QEMU. Jusqu'à
# 6j, c'était la glibc de la machine qui construit : l'image dépendait de
# l'Ubuntu de l'hôte, et WSL et la CI n'avaient la même que tant qu'apt les
# mettait à jour ensemble. Écarté : une empreinte attendue de la glibc de la
# machine (elle arrêterait la construction à chaque mise à jour de sécurité
# d'Ubuntu, sans dire laquelle prendre). La révision figée est celle de WSL
# et de la CI en novembre 2026 : la même libc.so.6, octet pour octet.
# ldconfig vient de la même version de la glibc que ld-linux (libc-bin, à
# côté de libc6 : le même paquet source), le format du cache en dépend
# (ldconfig.real : ldconfig n'est chez Ubuntu qu'un script autour de lui).
# Les paquets sont extraits dans un dossier à part, mis en place d'un coup
# (deux constructions à la fois, le dossier de travail et un worktree, ne
# voient jamais une glibc à moitié écrite), et les fichiers copiés sont
# revérifiés à chaque construction par leurs empreintes, comme claude.
# Ce qui reste de la machine : nos programmes de test dynamiques
# (bonjour-c-dynamique, dynamique, libessai.so) sont compilés par son gcc
# contre son libc6-dev ; une machine à glibc plus récente pourrait leur faire
# demander des symboles que la 2.39 n'a pas (ld-linux le dirait au
# lancement).
#
# La copie est refaite chaque fois que le CONTENU de ce qui y entre change
# (libessai.so, ld.so.conf, ou une autre révision), pas sa date : une
# empreinte (sha256), recalculée à chaque construction (FORCE) et gardée
# dans .copiee.
# (GLIBC, GLIBC_SOURCE et GLIBC_FICHIERS sont définis plus haut, avec LINUX :
# make lit les prérequis d'une règle dès qu'il la rencontre.)
$(GLIBC_PAQUETS)/.extraits:
	mkdir -p $(dir $(GLIBC_PAQUETS))
	neuf=$$(mktemp -d $(GLIBC_PAQUETS).XXXXXX) && trap 'rm -rf "$$neuf"' EXIT && cd "$$neuf" && \
	  curl -sSfL -o libc6.deb $(GLIBC_ADRESSE)/libc6_$(GLIBC_VERSION)_amd64.deb && \
	  curl -sSfL -o libc-bin.deb $(GLIBC_ADRESSE)/libc-bin_$(GLIBC_VERSION)_amd64.deb && \
	  printf '%s  libc6.deb\n%s  libc-bin.deb\n' $(GLIBC_SHA256_LIBC6) $(GLIBC_SHA256_LIBC_BIN) | sha256sum -c --quiet && \
	  dpkg-deb -x libc6.deb racine && dpkg-deb -x libc-bin.deb racine && rm -f libc6.deb libc-bin.deb && \
	  sha256sum $(addprefix racine/usr/lib/x86_64-linux-gnu/,$(GLIBC_FICHIERS)) racine/usr/sbin/ldconfig.real > empreintes && \
	  touch .extraits && \
	  { mv -T "$$neuf" $(GLIBC_PAQUETS) 2>/dev/null || true; }
	test -f $@

COPIE_GLIBC = $(addprefix $(GLIBC_SOURCE)/,$(GLIBC_FICHIERS)) racine/etc/ld.so.conf $(LINUX)/libessai.so
$(GLIBC)/.copiee: $(GLIBC_PAQUETS)/.extraits $(LINUX)/libessai.so FORCE
	@(cd $(GLIBC_PAQUETS) && sha256sum -c --quiet empreintes) || \
	  { echo "$(GLIBC_PAQUETS) ne correspond plus a ses empreintes : l'effacer"; exit 1; }
	@empreinte=$$(sha256sum $(COPIE_GLIBC) | sha256sum | cut -d ' ' -f 1); \
	test "$$(cat $@ 2>/dev/null)" != "$$empreinte" || exit 0; \
	set -ex; \
	rm -rf $(GLIBC); \
	mkdir -p $(GLIBC)/racine/usr/lib/x86_64-linux-gnu $(GLIBC)/racine/usr/local/lib $(GLIBC)/racine/etc; \
	cp $(addprefix $(GLIBC_SOURCE)/,$(GLIBC_FICHIERS)) $(GLIBC)/racine/usr/lib/x86_64-linux-gnu/; \
	cp $(LINUX)/libessai.so $(GLIBC)/racine/usr/local/lib/; \
	ln -s usr/lib $(GLIBC)/racine/lib; \
	cp racine/etc/ld.so.conf $(GLIBC)/racine/etc/; \
	$(GLIBC_PAQUETS)/racine/usr/sbin/ldconfig.real -X -r $(GLIBC)/racine -C /etc/ld.so.cache -f /etc/ld.so.conf; \
	echo "$$empreinte" > $@

# L'archive des programmes de test : sa description est fabriquée ici, une
# ligne par programme (voir archive.sh), avec son /etc/demarrage
# (tests-demarrage.txt), qui les lance l'un après l'autre.
LECTEUR = lecteur/target/wasm32-unknown-unknown/release/lecteur.wasm
tests.cpio: archive.sh tests-demarrage.txt $(addprefix $(LINUX)/tests/,$(TESTS_LINUX) $(TESTS_INTERP) $(TESTS_PARALLELES)) $(INTERPRETEURS) \
            $(LINUX)/bonjour-asm $(LINUX)/fils $(LINUX)/courses $(LINUX)/gestionnaires $(LINUX)/passerelle $(GLIBC)/.copiee FORCE
	cd lecteur && cargo build --release
	{ echo "dir /bin 755 0 0"; \
	  for p in $(TESTS_LINUX) $(TESTS_INTERP) $(TESTS_PARALLELES); do echo "file /bin/$$p $(LINUX)/tests/$$p 755 0 0"; done; \
	  echo "file /bin/lecteur.wasm $(LECTEUR) 755 0 0"; \
	  echo "file /bin/bonjour-asm $(LINUX)/bonjour-asm 755 0 0"; \
	  echo "file /bin/fils $(LINUX)/fils 755 0 0"; \
	  echo "file /bin/courses $(LINUX)/courses 755 0 0"; \
	  echo "file /bin/gestionnaires $(LINUX)/gestionnaires 755 0 0"; \
	  echo "file /bin/passerelle $(LINUX)/passerelle 755 0 0"; \
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
# le droit d'exécution ; 9 : --tcplisten= devant un programme Linux ; 10 :
# --tcplisten= sans port ; 11 : deux écoutes à la même adresse, la seconde
# refusée par EADDRINUSE, et la première fermée avec elle, le programme
# n'est pas lancé ; 12 : une redirection d'un fichier absent ; 13 : une
# redirection pour un programme WebAssembly ; 14 : `<<`, une autre
# redirection de sh, refusée ; 15 : cd vers un dossier absent ; 16 : cd
# vers un fichier ; 17 : cd par un chemin relatif ; 18-19 : un groupe vide ;
# 20-23 : un groupe dont une ligne est refusée, refusé en entier ; 24-27 : un
# programme lancé par & sans wait dans un groupe ; 28 : } seul) ; puis chaque
# programme de TESTS_LINUX et de
# TESTS_INTERP, ceux de TESTS_PARALLELES par deux, un fil qui fait une
# faute (fils faute : tout le groupe meurt), les courses entre fils et les
# gestionnaires de signaux (sous qemu64 et max, en plus de Nehalem au
# démarrage : sans XSAVE, puis avec XSAVE et AVX), les erreurs ICMP d'une
# adresse muette (passerelle muet : 10.0.2.99, que le noyau des tests a
# déjà vue échouer au démarrage), lecteur.wasm sans dossier pré-ouvert, et
# bonjour-asm.
tests-demarrage.txt: Makefile
	{ echo "# Fabrique par le Makefile (tests.cpio)."; \
	  echo "/bin/bonjour-asm \"pas ferme"; \
	  echo "--dir=/ /bin/bonjour-asm"; \
	  echo "bin/bonjour-asm"; \
	  echo "/bin/absent"; \
	  echo "/bin"; \
	  echo "/bin/bonjour-asm/"; \
	  echo "/etc/demarrage"; \
	  echo "--tcplisten=127.0.0.1:8080 /bin/bonjour-asm"; \
	  echo "--tcplisten=127.0.0.1 /bin/lecteur.wasm"; \
	  echo "--tcplisten=127.0.0.1:8080 --tcplisten=127.0.0.1:8080 /bin/lecteur.wasm"; \
	  echo "/bin/bonjour-asm < /absent"; \
	  echo "/bin/lecteur.wasm < /etc/demarrage"; \
	  echo "/bin/bonjour-asm <<x"; \
	  echo "cd /absent"; \
	  echo "cd /etc/demarrage"; \
	  echo "cd tmp"; \
	  echo "{"; echo "}"; \
	  echo "{"; echo "/bin/lecteur.wasm groupe-refuse"; echo "/bin/bonjour-asm \"pas ferme"; echo "}"; \
	  echo "{"; echo "/bin/lecteur.wasm groupe-refuse &"; echo "/bin/lecteur.wasm groupe-refuse"; echo "}"; \
	  echo "}"; \
	  for p in $(TESTS_LINUX) $(TESTS_INTERP); do echo "/bin/$$p"; done; \
	  echo "/bin/lignes a 200 &"; \
	  echo "/bin/lignes b 200 &"; \
	  echo "wait"; \
	  echo "/bin/cible &"; \
	  echo "/bin/signaler"; \
	  echo "wait"; \
	  echo "/bin/avx a b &"; \
	  echo "/bin/avx b a &"; \
	  echo "wait"; \
	  echo "/bin/oom-gros &"; \
	  echo "/bin/oom-petit"; \
	  echo "wait"; \
	  echo "/bin/fils faute"; \
	  echo "/bin/courses"; \
	  echo "/bin/gestionnaires"; \
	  echo "/bin/passerelle muet"; \
	  echo "/bin/lecteur.wasm"; \
	  echo "/bin/bonjour-asm"; } > $@

PROGRAMMES_HOTE = $(addprefix $(LINUX)/,bonjour-asm bonjour-asm.o bonjour-asm-wx bonjour-asm-pile-executable bonjour-c bonjour-c-deux-segments bonjour-c-pie bonjour-c-dynamique)

# Le vrai `claude` (6d), Claude Code 2.1.310 : le binaire du paquet npm
# officiel de la plateforme (@anthropic-ai/claude-code-linux-x64, celui que
# la fonctionnalité claude-code du devcontainer installe), téléchargé une
# fois, à une version figée, et vérifié par l'empreinte SHA-256 DU BINAIRE
# (c'est lui qu'on exécute), comme wabt. Gardé hors du dépôt, dans un cache
# que partagent les sous-étapes suivantes : jamais commité ni publié (« All
# rights reserved ») ; l'image boot.bin qui le contient ne l'est pas non
# plus (*.bin). L'archive npm est lue en flux : seul package/claude en
# sort, dans un fichier temporaire, renommé une fois la somme vérifiée
# (une copie à moitié écrite ne sert jamais). Ce fichier a un nom à lui
# (mktemp) : deux constructions qui téléchargent en même temps (le dossier
# de travail et un worktree de verifier-historique, qui partagent le
# cache) n'écrivent pas le même ; et il est effacé quoi qu'il arrive
# (trap), même par un Ctrl+C pendant curl. Le nom du binaire porte son
# empreinte : une autre empreinte est un autre fichier, téléchargé à son
# tour. Et l'empreinte est revérifiée à chaque construction de l'archive
# (une demi-seconde) : un fichier du cache abîmé ou remplacé n'entre
# jamais dans l'image. Pas de cache de la CI pour lui (`actions/cache` se
# lit depuis une demande de fusion venue d'une copie du dépôt) : la CI le
# télécharge à chaque fois.
CLAUDE_VERSION = 2.1.310
CLAUDE_URL     = https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/claude-code-linux-x64-$(CLAUDE_VERSION).tgz
CLAUDE_SHA256  = b73676430af12f97316a798b8371f81d640f90a58bdcb8f3ce56a835bb47df56
CLAUDE_CACHE   = $(HOME)/.cache/claude-os
CLAUDE         = $(CLAUDE_CACHE)/claude-$(CLAUDE_VERSION)-$(CLAUDE_SHA256)

$(CLAUDE):
	mkdir -p $(CLAUDE_CACHE)
	tmp=$$(mktemp $(CLAUDE_CACHE)/.telechargement.XXXXXX) && trap 'rm -f "$$tmp"' EXIT && \
	curl -sSfL $(CLAUDE_URL) | tar -xzO package/claude > "$$tmp" && \
	echo "$(CLAUDE_SHA256)  $$tmp" | sha256sum -c --quiet && \
	chmod 755 "$$tmp" && mv "$$tmp" $@

# L'archive de démarrage, décrite par archive.txt, et le binaire de claude
# (son chemin est celui du cache, que la description ne peut pas nommer :
# le Makefile ajoute sa ligne) : le noyau la déballe, puis lance ce que dit
# son /etc/demarrage (voir archive.sh).
programmes.cpio: $(CLAUDE) archive.sh archive.txt racine/etc/bonjour.txt racine/etc/demarrage racine/etc/ld.so.conf $(GLIBC)/.copiee $(LINUX)/bonjour-asm $(LINUX)/pile $(LINUX)/sse $(LINUX)/bonjour-c $(LINUX)/bonjour-c-pie $(LINUX)/bonjour-c-dynamique $(LINUX)/dynamique $(LINUX)/libessai.so $(LINUX)/memoire $(LINUX)/claude-version $(LINUX)/temps $(LINUX)/fichiers $(LINUX)/arbre $(LINUX)/segments $(LINUX)/signaux $(LINUX)/gestionnaires $(LINUX)/reprise $(LINUX)/suspendre $(LINUX)/attente $(LINUX)/tubes $(LINUX)/systeme $(LINUX)/processeurs $(LINUX)/evenements $(LINUX)/proc $(LINUX)/partage $(LINUX)/ajout $(LINUX)/clone $(LINUX)/fils $(LINUX)/courses $(LINUX)/fautes $(LINUX)/troncature $(LINUX)/redirections $(LINUX)/dossier $(LINUX)/effacer $(LINUX)/copies $(LINUX)/surveillance $(LINUX)/reseau $(LINUX)/dns $(LINUX)/aleatoire $(LINUX)/tcp $(LINUX)/proprietaire $(LINUX)/autocode $(LINUX)/unix $(LINUX)/client-tcp $(LINUX)/telecharger $(LINUX)/passerelle \
              racine/etc/hosts racine/etc/nsswitch.conf FORCE
	echo "$(CLAUDE_SHA256)  $(CLAUDE)" | sha256sum -c --quiet
	cd bonjour && cargo build --release
	cd lecteur && cargo build --release
	cd bonjour-tcp && cargo build --release
	{ cat archive.txt; echo "file /usr/local/bin/claude $(CLAUDE) 755 0 0"; } | sh archive.sh $@ -

# L'archive du jalon de 6f à 6i : celle de l'étape, dont /etc/demarrage ne
# lance que claude -p, deux fois, puis la liste de ce qu'il a laissé dans
# HOME et dans /tmp, et son effacement (racine/etc/demarrage-claude-p).
claude-p.cpio: programmes.cpio racine/etc/demarrage-claude-p
	{ sed 's|racine/etc/demarrage |racine/etc/demarrage-claude-p |' archive.txt; echo "file /usr/local/bin/claude $(CLAUDE) 755 0 0"; } \
	  | sh archive.sh $@ -

# L'archive de la machine sans carte (6g) : celle de l'étape sans claude,
# dont /etc/demarrage ne lance que `passerelle sans-reseau`.
sans-reseau.cpio: programmes.cpio racine/etc/demarrage-sans-reseau
	sed 's|racine/etc/demarrage |racine/etc/demarrage-sans-reseau |' archive.txt | sh archive.sh $@ -

# Le scénario du NMI (make tests-qemu) : l'archive de l'étape, dont
# /etc/demarrage ne lance que `processeurs boucle` (racine/etc/demarrage-nmi).
nmi.cpio: programmes.cpio racine/etc/demarrage-nmi
	sed 's|racine/etc/demarrage |racine/etc/demarrage-nmi |' archive.txt | sh archive.sh $@ -

nmi.bin: nmi.cpio FORCE
	cd noyau && cargo build --release
	$(call image,$(NOYAU_ELF),nmi.cpio,nmi)

sans-reseau.bin: sans-reseau.cpio FORCE
	cd noyau && cargo build --release
	$(call image,$(NOYAU_ELF),sans-reseau.cpio,sans-reseau)

claude-p.bin: claude-p.cpio FORCE
	cd noyau && cargo build --release
	$(call image,$(NOYAU_ELF),claude-p.cpio,claude-p)

# Le temps que met claude -p dans QEMU sans accélération (28 s mesurées ici
# en 6f ; 33 s en 6g, l'image construite comprise, avec le DNS et la
# connexion refusée ; en 6i, ses deux lancements et le groupe, 19 s ; en 6j,
# sur quatre processeurs, 18 s : claude -p est une boucle d'événements et
# du réseau, peu de calcul à répartir ; le double ou plus sur une machine
# de la CI).
DUREE_CLAUDE_P = 240

# claude -p bonjour, deux fois, dans notre noyau (racine/etc/demarrage-
# claude-p) : il doit aller jusqu'à l'appel de l'API, trouver son adresse
# par le DNS, s'y connecter par notre TCP, et rapporter ce que l'API répond
# à une fausse clé, par TLS (« Invalid API key ») ; puis, contre la fausse
# API, afficher sa réponse et finir par 0 (claude-p-attendu.txt). Les deux
# lancements, la liste de ce qu'ils ont laissé dans HOME et dans /tmp, puis
# son effacement, forment un groupe, qui doit rendre toute sa mémoire.
#
# On attend la ligne du groupe, la dernière ; si QEMU s'arrête avant, ou au
# bout de DUREE_CLAUDE_P, les lignes qui manquent le disent.
claude-p: claude-p.bin
	rm -f claude-p.log; \
	timeout $(DUREE_CLAUDE_P) $(QEMU_TEST) -drive format=raw,file=claude-p.bin,if=$(QEMU_DISQUE) $(QEMU_OPTIONS) \
	  -serial file:claude-p.log & q=$$!; \
	for i in $$(seq $$(( $(DUREE_CLAUDE_P) * 10 ))); do \
	  grep -qF -- "[noyau] Groupe des lignes" claude-p.log 2>/dev/null && break; kill -0 $$q 2>/dev/null || break; sleep 0.1; \
	done; \
	kill $$q 2>/dev/null; wait $$q 2>/dev/null; \
	grep -E "API Error|API key|fausse API|claude : termine|Groupe des lignes" claude-p.log; \
	while IFS= read -r ligne; do \
	  grep -qF -- "$$ligne" claude-p.log || { echo "claude -p : manque « $$ligne »"; exit 1; }; \
	done < claude-p-attendu.txt

# Le jalon de 6i : la vraie réponse de Claude, avec l'abonnement de David.
#
# Le jeton (make jeton, outils/jeton-claude) est un fichier de sa machine,
# hors du dépôt et hors de ~/.claude (que parcourent les sessions de Claude
# Code). Il ne passe que de fichier à fichier : jamais par une variable de
# make ou du shell, jamais sur une ligne de commande. Le Makefile ne connaît
# que son chemin.
#
# make claude-bonjour construit l'image dans un dossier à part, PRIVE
# (0700, umask 077 : tout ce qui y naît est à David seul), puisque son
# archive porte le jeton (/etc/claude/jeton, 0400, à l'utilisateur 1000 ;
# voir racine/etc/demarrage-claude-bonjour) : ni dans le dossier de l'étape, ni
# dans le dépôt. Ses fichiers sont effacés avant (ce qu'un arrêt brutal
# aurait laissé) et après, quoi qu'il arrive : la commande entière tourne
# dans un seul shell, dont le piège (trap) les efface à sa sortie, et qui
# construit l'archive et l'image par un make de plus (pour garder une seule
# recette de l'image, la macro image). On efface ces fichiers-là, par leurs
# noms, puis le dossier s'il est vide, plutôt que tout le dossier : un
# effacement récursif d'un chemin fait de variables ferait trop de dégâts
# si l'une d'elles était fausse.
#
# Ni la mémoire du système invité dans un fichier core de QEMU (elle garde
# le jeton) : -machine dump-guest-core=off la retire de tout vidage
# (madvise MADV_DONTDUMP). ulimit -c 0 ne suffirait pas : quand
# core_pattern est un tube (WSL : |/wsl-capture-crash), Linux ignore
# RLIMIT_CORE (fs/coredump.c) ; on le garde pour les autres fichiers. Ni
# moniteur de QEMU. Un Ctrl-C arrête QEMU avant
# d'effacer : un programme lancé par & dans un shell sans contrôle des
# tâches ignore SIGINT, il faut le tuer soi-même.
#
# Puis on attend la ligne du groupe, comme make claude-p, et on montre ce
# que le noyau et Claude ont écrit sur le port série depuis le lancement,
# sans le détail des chargements ; réussi si Claude finit par 0.
JETON = $(HOME)/.config/claude-os/jeton
PRIVE = $(HOME)/.config/claude-os/image
PRIVE_FICHIERS = $(addprefix $(PRIVE)/,claude-bonjour.cpio claude-bonjour-noyau.bin claude-bonjour-chargeur.bin claude-bonjour.bin serie.log)
DUREE_CLAUDE_BONJOUR = $(DUREE_CLAUDE_P)

jeton:
	sh outils/jeton-claude $(JETON)

claude-bonjour:
	@test -s $(JETON) || { echo "make claude-bonjour : pas de jeton ($(JETON)) : claude setup-token dans un terminal, puis make jeton"; exit 1; }
	umask 077; ulimit -c 0; q=; \
	trap 'rm -f $(PRIVE_FICHIERS); rmdir $(PRIVE) 2>/dev/null' EXIT; \
	trap 'test -n "$$q" && kill $$q 2>/dev/null; exit 130' INT TERM HUP; \
	rm -f $(PRIVE_FICHIERS); mkdir -p $(PRIVE); chmod 700 $(PRIVE); \
	$(MAKE) --no-print-directory $(PRIVE)/claude-bonjour.bin || exit 1; \
	timeout $(DUREE_CLAUDE_BONJOUR) $(QEMU_TEST) -machine dump-guest-core=off \
	  -drive format=raw,file=$(PRIVE)/claude-bonjour.bin,if=$(QEMU_DISQUE) $(QEMU_OPTIONS) \
	  -serial file:$(PRIVE)/serie.log & q=$$!; \
	for i in $$(seq $$(( $(DUREE_CLAUDE_BONJOUR) * 10 ))); do \
	  grep -qF -- "[noyau] Groupe des lignes" $(PRIVE)/serie.log 2>/dev/null && break; kill -0 $$q 2>/dev/null || break; sleep 0.1; \
	done; \
	kill $$q 2>/dev/null; wait $$q 2>/dev/null; \
	sed -n '/Lancement/,$$p' $(PRIVE)/serie.log | grep -v -E '^        |programme Linux \(ELF|Piles du noyau'; \
	grep -qF -- "[noyau] claude : termine, code de sortie 0" $(PRIVE)/serie.log

# L'archive et l'image de make claude-bonjour, dans PRIVE (que seul make
# claude-bonjour prépare, puis vide) : celles de l'étape, dont
# /etc/demarrage lance Claude avec le jeton, qu'elles portent en plus.
$(PRIVE)/claude-bonjour.cpio: programmes.cpio racine/etc/demarrage-claude-bonjour $(JETON)
	{ sed 's|racine/etc/demarrage |racine/etc/demarrage-claude-bonjour |' archive.txt; echo "file /usr/local/bin/claude $(CLAUDE) 755 0 0"; \
	  echo "dir /etc/claude 500 1000 1000"; echo "file /etc/claude/jeton $(JETON) 400 1000 1000"; } | sh archive.sh $@ -

$(PRIVE)/claude-bonjour.bin: $(PRIVE)/claude-bonjour.cpio FORCE
	cd noyau && cargo build --release
	$(call image,$(NOYAU_ELF),$<,$(PRIVE)/claude-bonjour)

FORCE:

run: boot.bin
	$(QEMU) -serial stdio

texte: boot.bin
	$(QEMU) -display curses -serial file:serial.log

# Le temps que met l'étape à démarrer et à exécuter toute son archive,
# sous QEMU sans accélération, avec de la marge. Depuis 6d, l'archive porte
# claude (307 Mo) : lue en 3,8 s (sur un disque virtio), déballée en 1 s,
# puis tous les programmes, claude --version compris (0,45 s) ; en 6e,
# avec les programmes à plusieurs fils et leurs temps d'attente (partage,
# dort, courses), 8,8 s en tout, mesurées sur une machine tranquille. En 6c, 3,8 s devenaient
# 14,6 s quand trois relectures se partageaient les 12 cœurs de la
# machine : d'où la marge. En 6h, les temps d'attente de tcp (le SYN sans
# réponse, 3 s ; le keepalive, 2,5 s ; SO_LINGER, 1 s) et ses 64 Mio
# (1,1 s) : 26 s en tout au milieu de l'étape, 39 s à sa fin (tcp seul :
# 17 s), mesurées en 6i ; d'où 90 s depuis, le double. En 6i, les fautes
# disputées par des fils (fautes, quatre fois), les troncatures (3 s), un
# programme ouvert en écriture qu'un groupe attend (1,5 s), inotify (sa
# file pleine, ses 128 instances, ses guetteurs : 2 s d'attente) : 48 s
# en tout, mesurées. En 6j, les tests du multiprocesseur au démarrage (la
# torture : 400 000 prises d'un Verrou, 20 000 d'un Mutex, 8 000 réveils
# croisés ; les vingt parties du tour des verrous qui dorment ; le TLB) et
# les programmes à fils sur quatre processeurs (fautes, processeurs) : 54 s
# en tout, mesurées (QEMU sans accélération, quatre processeurs virtuels
# sur quatre fils de l'hôte) ; d'où 120 s, le double. verifier.sh le
# demande par `make duree` ; ne pas le lancer sur une machine saturée.
DUREE = 120

duree:
	@echo $(DUREE)

# Pour verifier.sh : l'interface du disque, et les autres options de QEMU.
qemu-disque:
	@echo $(QEMU_DISQUE)

qemu-options:
	@echo $(QEMU_OPTIONS)

test: boot.bin
	-timeout $(DUREE) $(QEMU) -display none -no-reboot -serial file:serial.log
	@cat serial.log

debug: boot.bin
	-timeout $(DUREE) $(QEMU) -display none -no-reboot -serial file:serial.log \
	  -d int,cpu_reset -D qemu.log
	@cat serial.log
	@echo "--- exceptions (v=numero, e=code d'erreur) ---"
	@grep -E "^ *[0-9]+: v=|Triple fault" qemu.log | grep -v "v=08 e=0000 i=1" | head -20 || true

# Une virgule, à passer dans un argument de $(call), qui les sépare.
, := ,

# Lance QEMU ($(1), en arrière-plan) et attend que le fichier $(2) (son
# port série) contienne la ligne $(3), au plus DUREE secondes, puis
# l'arrête (par son numéro de processus) ; $(4) s'exécute juste avant. Le
# code de sortie dit si la ligne est venue. Plutôt qu'un délai fixe : un
# démarrage plus lent (une machine chargée) attend plus, un plus rapide
# n'attend pas pour rien.
define attendre
	rm -f $(2); $(1) & q=$$!; \
	for i in $$(seq $$(( $(DUREE) * 10 ))); do \
	  grep -qF -- $(3) $(2) 2>/dev/null && break; kill -0 $$q 2>/dev/null || break; sleep 0.1; \
	done; \
	$(4); kill $$q 2>/dev/null; wait $$q 2>/dev/null; grep -F -- $(3) $(2)
endef

# L'écran une fois claude terminé : la lecture de l'archive (3,8 s) le
# laisserait sinon au chargeur.
capture: boot.bin
	rm -f $(MON) ecran.png
	$(call attendre,$(QEMU) -display none -serial file:capture.log -monitor unix:$(MON)$(,)server$(,)nowait,capture.log,"claude : termine",\
	  echo "screendump ecran.png -f png" | nc -U -q1 $(MON) >/dev/null)
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

tests-hote: $(SUITE)/.convertie $(CLAUDE) $(PROGRAMMES_HOTE) $(LINUX)/memoire $(LINUX)/claude-version $(LINUX)/temps $(LINUX)/fichiers $(LINUX)/segments $(LINUX)/dynamique $(LINUX)/libessai.so \
            $(LINUX)/signaux $(LINUX)/gestionnaires $(LINUX)/reprise $(LINUX)/suspendre $(LINUX)/attente $(LINUX)/tubes $(LINUX)/systeme $(LINUX)/processeurs $(LINUX)/evenements $(LINUX)/proc $(LINUX)/ajout $(LINUX)/clone \
            $(LINUX)/fils $(LINUX)/courses $(LINUX)/fautes $(LINUX)/troncature $(LINUX)/redirections $(LINUX)/dossier $(LINUX)/effacer $(LINUX)/copies $(LINUX)/surveillance $(LINUX)/reseau $(LINUX)/dns $(LINUX)/aleatoire $(LINUX)/tcp $(LINUX)/unix $(LINUX)/proprietaire $(LINUX)/autocode
	cd formats && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd formats && CLAUDE_BINAIRE=$(CLAUDE) cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd zones && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd zones && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd fichiers && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd fichiers && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd inet && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd inet && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd crypto && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd crypto && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd roue && cargo build --target x86_64-unknown-none 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	cd roue && cargo test --release 2>&1 | tee /dev/stderr | (! grep -q '^warning')
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
	timeout 60 ./$(LINUX)/gestionnaires | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/reprise | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/suspendre | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/attente | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/tubes | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 10 ./$(LINUX)/tubes sigpipe; test $$? = 141
	./$(LINUX)/systeme | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/processeurs | tee /dev/stderr | grep -q "toutes les verifications : ok"
	./$(LINUX)/evenements | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/proc | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/clone | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/fils | tee /dev/stderr | grep -q "toutes les verifications : ok"
	./$(LINUX)/fils groupe; test $$? = 7
	./$(LINUX)/courses | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/fautes | tee /dev/stderr | (! grep -q ECHEC)
	./$(LINUX)/fautes fin
	./$(LINUX)/troncature lecture 1500 /dev/shm | tee /dev/stderr | grep -q "troncature : .* : ok"
	./$(LINUX)/troncature copie 1500 /dev/shm | tee /dev/stderr | grep -q "troncature : .* : ok"
	mkdir -p $(LINUX)/redirige && echo bonjour > $(LINUX)/redirige/a && echo jeton > $(LINUX)/redirige/b && \
	  ./$(LINUX)/redirections $(LINUX)/redirige/a $(LINUX)/redirige/b < $(LINUX)/redirige/a 3< $(LINUX)/redirige/b \
	  | tee /dev/stderr | grep -q "redirections : .* : ok"
	env -i /bin/sh -c "cd / && $(CURDIR)/$(LINUX)/dossier / / '*' && cd /tmp && $(CURDIR)/$(LINUX)/dossier /tmp /tmp / \
	  && cd /etc/../tmp// && $(CURDIR)/$(LINUX)/dossier /tmp /tmp /tmp" | tee /dev/stderr | test $$(grep -c "dossier : .* : ok") = 3
	./$(LINUX)/effacer --creer $(LINUX)/effacer.d 6 && ./$(LINUX)/effacer --contenu $(LINUX)/effacer.d \
	  && ./$(LINUX)/effacer --creer $(LINUX)/effacer.d 3 && ./$(LINUX)/effacer $(LINUX)/effacer.d \
	  && test ! -e $(LINUX)/effacer.d
	./$(LINUX)/copies /dev/shm | tee /dev/stderr | grep -q "copies : toutes les verifications : ok"
	./$(LINUX)/surveillance /dev/shm | tee /dev/stderr | grep -q "surveillance : toutes les verifications : ok"
	timeout 60 ./$(LINUX)/reseau | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/dns | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/aleatoire | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 120 ./$(LINUX)/tcp | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/unix | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/proprietaire | tee /dev/stderr | grep -q "toutes les verifications : ok"
	timeout 60 ./$(LINUX)/autocode | tee /dev/stderr | grep -q "toutes les verifications : ok"
	if sudo -n true 2>/dev/null; then $(MAKE) tests-hote-root; else echo "tests-hote-root : pas de sudo, sautes"; fi
	rm -rf /tmp/ajout; \
	  ./$(LINUX)/ajout ecrire a 500 & a=$$!; ./$(LINUX)/ajout ecrire b 500 & b=$$!; \
	  ./$(LINUX)/ajout verifier 500 | tee /dev/stderr | (! grep -q ECHEC); r=$$?; wait $$a $$b; exit $$r

# La MTU du chemin sur l'hôte : le seul test qui demande root (une socket brute forge
# l'ICMP vers lo). Ce qu'il pose sur la route ne vise qu'une adresse 127.x.y.z tirée au
# hasard, et expire en 10 min. `tests-hote` le lance quand `sudo -n` marche.
tests-hote-root: $(LINUX)/pmtu $(LINUX)/options-ip
	sudo -n timeout 60 ./$(LINUX)/pmtu | tee /dev/stderr | grep -q "toutes les verifications : ok"
	sudo -n timeout 60 ./$(LINUX)/options-ip formats/tests/reseau/options-ip.txt | tee /dev/stderr | grep -q "toutes les verifications : ok"

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
#   - test-garde : déborder de la pile d'une tâche du noyau, que sa page
#     de garde (vmalloc) doit arrêter net, et le dire ;
#   - test-gros : un noyau de plus de 1 Mio, que le chargeur doit lire en
#     entier, chaque secteur à sa place ;
#   - test-programmes : l'archive des programmes de test (tests.cpio),
#     exécutés un par un en un seul démarrage ; le noyau doit arrêter
#     chaque programme fautif et continuer, puis éteindre QEMU (le
#     périphérique isa-debug-exit : QEMU sort avec le code 2 x valeur + 1).
#     Chaque ligne de tests-attendu.txt doit être dans ce qu'il affiche.
#     Trois fois : avec le processeur par défaut (qemu64), avec toutes les
#     fonctions que QEMU sait imiter (-cpu max : SMEP, SMAP, UMIP...), pour
#     passer aussi par les chemins « si le processeur l'a », et avec un
#     processeur AMD (-cpu EPYC, les soldes d'avant 6k) : le contournement
#     de SYSRET (cpu.rs, `bogue_sysret_ss`) reconnu, et SS rechargé à au
#     moins une bascule (le noyau compte ces rechargements, et le dit à la
#     fin) ; TCG n'imite pas le défaut lui-même, le chemin, si. Avec, en
#     plus, les lignes propres à chacun (tests-attendu-qemu64.txt,
#     tests-attendu-max.txt, tests-attendu-EPYC.txt). Rien des lignes d'un groupe refusé (6i : elles
#     lancent lecteur.wasm avec l'argument « groupe-refuse », qu'il
#     afficherait). Et aucun ECHEC dans le journal (depuis 6e :
#     « memoire rendue » de plusieurs groupes de programmes en parallèle
#     s'écrit pareil, un ECHEC serait caché par un ok ; cible dit ECHEC
#     si le signal ne l'a pas réveillée).
#   - sans tables ACPI (-machine pc,acpi=off), le noyau ordinaire sur
#     l'archive vide (vide.bin) : il doit revenir au 8259 et au PIT, le
#     dire, et le clavier doit être prêt (depuis 6e) ; sans APIC local,
#     pas de MSI-X pour la carte réseau, et il le dit (depuis 6g) ;
#   - un pont PCI (pci-bridge) et une seconde carte virtio-net derrière
#     lui, avec le noyau ordinaire sur l'archive vide : le parcours du bus
#     doit descendre par le pont, et trouver la carte sur le bus 1 que le
#     BIOS lui a donné (depuis 6g) ;
#   - une carte virtio-net sans MSI-X (vectors=0) : le pilote la laisse
#     éteinte, et le dit (6g) ;
#   - une carte virtio-net à deux entrées MSI-X (vectors=2) : une pour la
#     configuration, une pour les deux files, et le DHCP passe par elle
#     (les soldes d'avant 6k) ;
#   - vingt datagrammes de l'hôte, d'un coup, vers un port fermé de la
#     machine (slirp les fait suivre, `hostfwd`, depuis 10.0.2.2) : six
#     erreurs ICMP « port injoignable », pas plus, la limite par machine
#     de Linux (inet::pairs) ; ce qui sort de la carte est lu dans
#     l'enregistrement de QEMU (`filter-dump`, un fichier pcap, compté par
#     outils/erreurs-icmp.awk). Le port de l'hôte est tiré au hasard ; s'il
#     est pris (QEMU s'arrête aussitôt), un autre (les soldes d'avant 6k) ;
#   - une carte sur un réseau sans serveur DHCP (-netdev hubport, un
#     concentrateur relié à rien) : le DHCP abandonne au bout de 12 à 17 s,
#     et le démarrage continue (6g) ;
#   - le câble débranché puis rebranché au moniteur (set_link) : chaque
#     fois, l'interruption de configuration de la carte, par MSI-X, et le
#     noyau le dit (6g) ;
#   - une machine sans carte (-nic none : sans cette option, QEMU ajoute
#     une e1000), et `passerelle sans-reseau` : le DNS de la glibc échoue
#     vite, EAI_AGAIN (6g) ;
#   - un seul processeur (-smp 1), le noyau ordinaire sur l'archive vide :
#     la MADT ne liste aucun secondaire, et le noyau le dit (6j) ;
#   - un NMI envoyé par le moniteur de QEMU à TOUS les processeurs
#     virtuels (`nmi`), le noyau ordinaire pendant que `processeurs boucle`
#     (nmi.bin, racine/etc/demarrage-nmi) fait boucler deux fils sur getpid
#     sur les processeurs 1 et 2, les deux autres inactifs : le NMI frappe
#     l'anneau 3, l'entrée ou la sortie d'un appel système (le chemin
#     paranoïaque, avec la base de GS du programme) et `hlt` ; un seul
#     processeur dit l'exception et panique, les autres se taisent (6j) ;
#   - le processeur secondaire 1 qui tarde six secondes (test-retard, sous
#     -cpu Nehalem pour mesurer son retard au TSC) : abandonné au bout de
#     cinq, il trouve ABANDONNE et s'arrête sans un mot ; trois
#     processeurs en service, et le démarrage continue (6j) ;
#   - le TSC du premier secondaire tenu pour non accordé (test-tsc, le
#     noyau construit avec cette fonctionnalité, sous -cpu Nehalem : il
#     faut un TSC fiable pour le déclasser) : le TSC est déclassé en
#     marche, l'heure revient au tic sans sauter, le démarrage continue
#     (6j : sous QEMU, les TSC sont toujours accordés, ce chemin ne se
#     verrait jamais autrement) ;
#   - le secteur 0 d'une image aux octets du BPB abîmés (test-bpb) : le
#     démarrage va au bout pareil ;
#   test-garde, test-gros, le démarrage sans ACPI et celui du pont ne
#   s'éteignent pas : QEMU est arrêté dès que la ligne cherchée est venue
#   (`attendre`), au lieu d'attendre DUREE.
QEMU_TEST_1 = qemu-system-x86_64 -display none -no-reboot
QEMU_TEST = $(QEMU_TEST_1) $(QEMU_SMP)
# Le moniteur de QEMU pendant les programmes de test (une touche envoyée
# pendant que `dort` dort) : une socket dans le dossier de l'étape, pour
# que deux vérifications en même temps (le dossier de travail et un
# worktree de verifier-historique) ne se gênent pas.
MON_TESTS = mon-tests.sock
# 60 s pour les programmes de test : le double des 23 à 28 s mesurées en 6j
# sous -cpu qemu64, la règle de DUREE (6h). À 30 s, le scénario a manqué sa
# fin sous la charge d'une autre vérification (les soldes d'avant 6k).
QEMU_PROGRAMMES = timeout 60 qemu-system-x86_64 -display none -no-reboot $(QEMU_SMP) $(QEMU_RESEAU) \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 -drive format=raw,file=test-programmes.bin

# Le secteur 0 d'une image, ses octets 3 à 0x59 abîmés exprès : ce qu'y
# écrit un BIOS qui démarre sur une clé USB en croyant y trouver un BPB
# (boot.asm, « La place d'un BPB ») ; le démarrage doit aller au bout pareil.
test-bpb.bin: vide.bin
	cp vide.bin $@
	printf '%87s' '' | tr ' ' '\245' | dd of=$@ bs=1 seek=3 conv=notrunc status=none

tests-qemu: test-garde.bin test-gros.bin test-programmes.bin test-tsc.bin test-retard.bin vide.bin test-bpb.bin nmi.bin sans-reseau.bin claude-p
	$(call attendre,$(QEMU_TEST) $(QEMU_RESEAU) $(QEMU_ALEA) -drive format=raw$(,)file=test-garde.bin -serial file:test-garde.log,test-garde.log,"debordement de la pile noyau d'une tache",:)
	$(call attendre,$(QEMU_TEST_1) -smp 1 $(QEMU_RESEAU) $(QEMU_ALEA) -drive format=raw$(,)file=vide.bin -serial file:test-smp1.log,test-smp1.log,"[noyau] 1 processeur en service : la MADT n'en liste pas d'autre.",:)
	$(call attendre,$(QEMU_TEST_1) -smp 1 $(QEMU_RESEAU) $(QEMU_ALEA) -drive format=raw$(,)file=test-bpb.bin -serial file:test-bpb.log,test-bpb.log,"[noyau] 1 processeur en service : la MADT n'en liste pas d'autre.",:)
	$(call attendre,$(QEMU_TEST) -cpu Nehalem $(QEMU_RESEAU) $(QEMU_ALEA) -drive format=raw$(,)file=test-tsc.bin -serial file:test-tsc.log,test-tsc.log,"[noyau] Heure (UTC)",:)
	grep -F "[noyau] TSC : le processeur 1 n'est pas accorde avec le premier (recul de 1000000 cycles, pas de TSC_ADJUST) : l'heure au tic, decalage de " test-tsc.log
	grep -F "[noyau] 4 processeurs en service." test-tsc.log
	grep -F "[noyau] 100 ms plus tard : " test-tsc.log
	$(call attendre,$(QEMU_TEST) -cpu Nehalem $(QEMU_RESEAU) $(QEMU_ALEA) -drive format=raw$(,)file=test-retard.bin -serial file:test-retard.log,test-retard.log,"[noyau] Heure (UTC)",:)
	grep -F "[noyau] Processeur 1 (APIC 1) ne repond pas : abandonne." test-retard.log
	grep -F "[noyau] 3 processeurs en service." test-retard.log
	! grep -F "Processeur 1 (APIC 1) en service" test-retard.log
	! grep -E "ECHEC|PANIQUE" test-retard.log
	rm -f test-nmi.log $(MON_TESTS); \
	$(QEMU_TEST) $(QEMU_RESEAU) $(QEMU_ALEA) -drive format=raw,file=nmi.bin -serial file:test-nmi.log -monitor unix:$(MON_TESTS),server,nowait & q=$$!; \
	ligne() { for i in $$(seq $$(( $(DUREE) * 10 ))); do grep -qF -- "$$1" test-nmi.log 2>/dev/null && return 0; \
	  kill -0 $$q 2>/dev/null || return 1; sleep 0.1; done; return 1; }; \
	ligne "[linux] processeurs : 2 fils bouclent sur getpid" && echo "nmi" | nc -U -q1 $(MON_TESTS) >/dev/null && ligne "[noyau] PANIQUE"; r=$$?; \
	kill $$q 2>/dev/null; wait $$q 2>/dev/null; grep -F "EXCEPTION 2 (NMI)" test-nmi.log; \
	[ $$r -eq 0 ] && [ $$(grep -c "EXCEPTION 2 (NMI)" test-nmi.log) -eq 1 ] && [ $$(grep -c "PANIQUE" test-nmi.log) -eq 1 ]
	$(call attendre,$(QEMU_TEST) $(QEMU_RESEAU) $(QEMU_ALEA) -machine pc$(,)acpi=off -drive format=raw$(,)file=vide.bin -serial file:test-sans-acpi.log,test-sans-acpi.log,"generateur laisse eteint.",:)
	grep -F "PIC 8259 (pas de tables ACPI) remappe sur les vecteurs 32-47" test-sans-acpi.log
	grep -F "MSI-X de 00:03.0 : pas d'APIC local : pas de MSI-X." test-sans-acpi.log
	grep -F "generateur laisse eteint." test-sans-acpi.log
	$(call attendre,$(QEMU_TEST) $(QEMU_RESEAU) $(QEMU_ALEA) -drive format=raw$(,)file=test-gros.bin -serial file:test-gros.log,test-gros.log,"chaque secteur a sa place : ok",:)
	$(call attendre,$(QEMU_TEST) $(QEMU_RESEAU) -device pci-bridge$(,)id=pont$(,)chassis_nr=1 -netdev user$(,)id=n1 \
	  -device virtio-net-pci$(,)netdev=n1$(,)bus=pont$(,)addr=1 -drive format=raw$(,)file=vide.bin -serial file:test-pont.log,test-pont.log,"[pci] 01:01.0 1af4:1000 Ethernet",:)
	grep -F "[pci] 00:04.0 1b36:0001 pont PCI, bus 1-1" test-pont.log
	$(call attendre,$(QEMU_TEST) -netdev hubport$(,)id=n0$(,)hubid=1 -device virtio-net-pci$(,)netdev=n0 -drive format=raw$(,)file=vide.bin \
	  -serial file:test-sans-dhcp.log,test-sans-dhcp.log,"[reseau] eth0 : pas de reponse DHCP (3 essais) : pas d'adresse.",:)
	$(call attendre,$(QEMU_TEST) -netdev user$(,)id=n0 -device virtio-net-pci$(,)netdev=n0$(,)vectors=0 -drive format=raw$(,)file=vide.bin \
	  -serial file:test-sans-msix.log,test-sans-msix.log,"[virtio] 00:03.0 : pas de MSI-X : carte laissee eteinte.",:)
	$(call attendre,$(QEMU_TEST) -netdev user$(,)id=n0 -device virtio-net-pci$(,)netdev=n0$(,)vectors=2 -drive format=raw$(,)file=vide.bin \
	  -serial file:test-deux-vecteurs.log,test-deux-vecteurs.log,"[reseau] eth0 : 10.0.2.15/24",:)
	grep -qF "une pour les deux files" test-deux-vecteurs.log
	rm -f test-icmp.log test-icmp.pcap; n=; \
	for essai in 1 2 3 4 5; do \
	  port=$$(( 20000 + ($$$$ * 31 + essai * 7919) % 40000 )); \
	  $(QEMU_TEST) -netdev user,id=n0,hostfwd=udp:127.0.0.1:$$port-:9 -device virtio-net-pci,netdev=n0 \
	    -object filter-dump,id=f0,netdev=n0,file=test-icmp.pcap -drive format=raw,file=vide.bin -serial file:test-icmp.log & q=$$!; \
	  etat=mort; for i in $$(seq $$(( $(DUREE) * 10 ))); do \
	    grep -qF "[reseau] eth0 : 10.0.2.15/24" test-icmp.log 2>/dev/null && { etat=pret; break; }; \
	    kill -0 $$q 2>/dev/null || { etat=mort; break; }; etat=lent; sleep 0.1; done; \
	  [ $$etat = mort ] && { wait $$q 2>/dev/null; continue; }; \
	  [ $$etat = pret ] && { bash -c 'exec 3>/dev/udp/127.0.0.1/'$$port'; for i in $$(seq 20); do printf x >&3; done'; sleep 2; \
	    n=$$(od -An -v -tu1 test-icmp.pcap | awk -f outils/erreurs-icmp.awk); }; \
	  kill $$q 2>/dev/null; wait $$q 2>/dev/null; break; \
	done; \
	[ "$$n" = 6 ] || { echo "ICMP par machine : $${n:-aucune mesure,} erreurs pour 20 datagrammes (6 attendues) : ECHEC"; exit 1; }; \
	echo "ICMP par machine : 6 erreurs pour 20 datagrammes : ok"
	$(call attendre,$(QEMU_TEST) -nic none $(QEMU_ALEA) -drive format=raw$(,)file=sans-reseau.bin -serial file:test-sans-reseau.log,test-sans-reseau.log,"[noyau] passerelle : termine",:)
	grep -F "[linux] passerelle : toutes les verifications (sans reseau) : ok" test-sans-reseau.log
	rm -f test-lien.log $(MON_TESTS); \
	$(QEMU_TEST) $(QEMU_RESEAU) $(QEMU_ALEA) -drive format=raw,file=vide.bin -serial file:test-lien.log -monitor unix:$(MON_TESTS),server,nowait & q=$$!; \
	ligne() { for i in $$(seq $$(( $(DUREE) * 10 ))); do grep -qF -- "$$1" test-lien.log 2>/dev/null && return 0; \
	  kill -0 $$q 2>/dev/null || return 1; sleep 0.1; done; return 1; }; \
	ligne "eth0 : virtio-net" && echo "set_link n0 off" | nc -U -q1 $(MON_TESTS) >/dev/null && \
	ligne "eth0 : lien coupe" && echo "set_link n0 on" | nc -U -q1 $(MON_TESTS) >/dev/null && \
	ligne "eth0 : lien retabli"; r=$$?; kill $$q 2>/dev/null; wait $$q 2>/dev/null; \
	grep -F "eth0 : " test-lien.log; exit $$r
	command -v nc >/dev/null || { echo "nc manque (paquet netcat-openbsd) : la touche de dort ne pourrait pas etre envoyee"; exit 1; }
	for cpu in qemu64 max EPYC; do \
	  journal=test-programmes-$$cpu.log; rm -f $$journal $(MON_TESTS); \
	  ( for i in $$(seq 300); do grep -qF "[linux] Test : dort" $$journal 2>/dev/null && break; sleep 0.1; done; \
	    echo "sendkey k" | nc -U -q1 $(MON_TESTS) >/dev/null 2>&1 ) & \
	  $(QEMU_PROGRAMMES) -cpu $$cpu -serial file:$$journal -monitor unix:$(MON_TESTS),server,nowait; code=$$?; \
	  [ $$code -eq 1 ] || { echo "-cpu $$cpu : QEMU n'a pas ete eteint par le noyau (code $$code)"; exit 1; }; \
	  sed -n '/Test : dort/,/dort : reveille/p' $$journal | grep -q k || { echo "-cpu $$cpu : la touche n'a pas ete affichee pendant que dort dormait"; exit 1; }; \
	  for nom in a b; do \
	    n=$$(grep -cE "^\[linux\] lignes $$nom [0-9]{4} $$nom{160}$$" $$journal); \
	    [ $$n -eq 200 ] || { echo "-cpu $$cpu : $$n lignes entieres de lignes $$nom sur 200"; exit 1; }; \
	  done; \
	  vus=$$(( 0x$$(sed -n 's/.*lignes a : processeurs vus : \([0-9a-f]*\).*/\1/p' $$journal | head -1) | 0x$$(sed -n 's/.*lignes b : processeurs vus : \([0-9a-f]*\).*/\1/p' $$journal | head -1) )); \
	  c=0; m=$$vus; while [ $$m -ne 0 ]; do c=$$(( c + (m & 1) )); m=$$(( m >> 1 )); done; \
	  [ $$c -ge 2 ] || { echo "-cpu $$cpu : les deux programmes lignes n'ont vu que $$c processeur(s) (masque $$vus)"; exit 1; }; \
	  while IFS= read -r ligne; do \
	    grep -qF -- "$$ligne" test-programmes-$$cpu.log || { echo "-cpu $$cpu : manque « $$ligne »"; exit 1; }; \
	  done < tests-attendu.txt; \
	  while IFS= read -r ligne; do \
	    grep -qF -- "$$ligne" test-programmes-$$cpu.log || { echo "-cpu $$cpu : manque « $$ligne »"; exit 1; }; \
	  done < tests-attendu-$$cpu.txt; \
	  [ $$cpu != EPYC ] || grep -qE '^\[noyau\] Processeur AMD : SS recharge a [1-9][0-9]* bascules' $$journal \
	    || { echo "-cpu EPYC : SS jamais recharge a une bascule"; exit 1; }; \
	  ! grep -n groupe-refuse $$journal || { echo "-cpu $$cpu : une ligne d'un groupe refuse a ete lancee"; exit 1; }; \
	  ! grep -n ECHEC $$journal || { echo "-cpu $$cpu : un ECHEC dans le journal"; exit 1; }; \
	done

# La trace des appels système : le noyau construit avec la fonctionnalité
# trace (son propre dossier de compilation), sur la machine de l'étape, avec
# l'archive de l'étape dont /etc/demarrage ne lance que claude --version
# (racine/etc/demarrage-trace : depuis 6j ; jouer tout le démarrage sous la
# trace prenait six minutes). Celle de claude --version dans notre noyau
# (elle n'affiche que des nombres : les registres de chaque appel), puis les
# NOMS des appels du même claude sous Linux, sur l'hôte : jamais une trace
# de claude qui pourrait contenir un jeton. Il est lancé sans
# environnement (env -i), avec un HOME neuf et vide : il n'a rien à lire ;
# la sortie de strace va dans un tuyau qui ne garde que le nom de chaque
# appel (`-o /dev/fd/3`), jamais au terminal ; ce qu'écrit claude, à
# /dev/null. Sous Linux, les horloges (clock_gettime...) passent par le
# vDSO, sans appel système : notre trace en a de plus (pas de vDSO avant
# 6n).
trace: test-trace.bin $(CLAUDE)
	$(call attendre,$(QEMU_TEST) -drive format=raw$(,)file=test-trace.bin$(,)if=$(QEMU_DISQUE) $(QEMU_OPTIONS) -serial file:trace.log,trace.log,"[noyau] claude : termine",:)
	@echo "--- dans notre noyau ---"
	@sed -n '/claude : programme/,/claude : termine/p' trace.log | grep -E '^\[(trace|linux)\]|claude :|Claude Code'
	@echo "--- sous Linux, sur l'hote (strace : les noms des appels seulement) ---"
	@command -v strace >/dev/null || { echo "strace manque (sudo apt install strace)"; exit 1; }
	@vide=$$(mktemp -d); \
	env -i HOME=$$vide strace -f -qq -o /dev/fd/3 $(CLAUDE) --version 3>&1 >/dev/null 2>&1 \
	  | sed -nE 's/^([0-9]+ +)?([a-z0-9_]+)\(.*/\2/p'; code=$${PIPESTATUS[0]}; \
	rm -rf $$vide; \
	test $$code -eq 0 || { echo "strace ou claude : code $$code (ptrace refuse ?)"; exit 1; }

test-trace.bin: trace.cpio FORCE
	cd noyau && cargo build --release --features trace --target-dir target/test-trace 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-trace/x86_64-unknown-none/release/noyau,trace.cpio,test-trace)

# L'archive de la trace : celle de l'étape, dont /etc/demarrage ne lance
# que claude --version (racine/etc/demarrage-trace).
trace.cpio: programmes.cpio racine/etc/demarrage-trace
	{ sed 's|racine/etc/demarrage |racine/etc/demarrage-trace |' archive.txt; echo "file /usr/local/bin/claude $(CLAUDE) 755 0 0"; } \
	  | sh archive.sh $@ -

# Les statistiques des verrous (6i) : le noyau construit avec la
# fonctionnalité verrous (son propre dossier de compilation), l'archive
# ordinaire ; après le démarrage, puis après chaque programme, les huit
# endroits qui ont gardé les interruptions coupées le plus longtemps
# (noyau/src/verrou.rs, `statistiques`). Sous QEMU sans accélération : 10 à
# 30 fois le temps d'un vrai processeur, les proportions comptent.
verrous: test-verrous.bin
	-timeout $(DUREE) qemu-system-x86_64 -display none -no-reboot -drive format=raw,file=test-verrous.bin,if=$(QEMU_DISQUE) \
	  $(QEMU_OPTIONS) -serial file:verrous.log
	@grep -E '^\[verrous\]|termine' verrous.log

test-verrous.bin: programmes.cpio FORCE
	cd noyau && cargo build --release --features verrous --target-dir target/test-verrous 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-verrous/x86_64-unknown-none/release/noyau,programmes.cpio,test-verrous)

# Les mêmes statistiques pendant `claude -p` (6j) : le noyau avec la
# fonctionnalité verrous sur l'archive de claude-p (la fausse API, sans
# jeton). Ce que les verrous courts ont attendu pendant les deux lancements
# (la contention : « attendu N fois, M us au plus »), et combien de fois les
# verrous qui dorment ont été pris en tournant ou en dormant : c'est ce qui
# décide d'un tas ou d'un générateur par processeur (tas.rs, aleatoire.rs).
verrous-claude-p: test-verrous-claude-p.bin
	rm -f test-verrous-claude-p.log; \
	timeout $(DUREE_CLAUDE_P) $(QEMU_TEST) -drive format=raw,file=test-verrous-claude-p.bin,if=$(QEMU_DISQUE) $(QEMU_OPTIONS) \
	  -serial file:test-verrous-claude-p.log & q=$$!; \
	for i in $$(seq $$(( $(DUREE_CLAUDE_P) * 10 ))); do \
	  grep -qF -- "[noyau] Groupe des lignes" test-verrous-claude-p.log 2>/dev/null && break; kill -0 $$q 2>/dev/null || break; sleep 0.1; \
	done; \
	kill $$q 2>/dev/null; wait $$q 2>/dev/null; \
	grep -E '^\[verrous\]|claude : termine|Groupe des lignes' test-verrous-claude-p.log

test-verrous-claude-p.bin: claude-p.cpio FORCE
	cd noyau && cargo build --release --features verrous --target-dir target/test-verrous 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-verrous/x86_64-unknown-none/release/noyau,claude-p.cpio,test-verrous-claude-p)

test-programmes.bin: tests.cpio FORCE
	cd noyau && cargo build --release --features test-programmes --target-dir target/test-programmes 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-programmes/x86_64-unknown-none/release/noyau,tests.cpio,test-programmes)

# Le noyau ordinaire sur l'archive vide : pour les scénarios qui ne
# regardent que le démarrage (sans tables ACPI : le repli sur le 8259).
vide.bin: vide.cpio FORCE
	cd noyau && cargo build --release
	$(call image,$(NOYAU_ELF),vide.cpio,vide)

# Les noyaux de test-garde et test-gros n'ont besoin d'aucun programme :
# une archive vide, un /etc/demarrage sans commande (celle de démarrage
# porte claude, 307 Mo, que ces scénarios liraient sur IDE avec 128 Mio ;
# celle des tests ferait tourner toute la suite pour rien).
vide.cpio: archive.sh
	printf 'dir /etc 755 0 0\nfile /etc/demarrage /dev/null 644 0 0\n' | sh archive.sh $@ -

test-%.bin: vide.cpio FORCE
	cd noyau && cargo build --release --features test-$* --target-dir target/test-$* 2>&1 | tee /dev/stderr | (! grep -q '^warning')
	$(call image,noyau/target/test-$*/x86_64-unknown-none/release/noyau,vide.cpio,test-$*)

clean:
	rm -f boot*.bin vide*.bin test-*.bin claude-p*.bin sans-reseau*.bin nmi*.bin programmes.cpio tests.cpio vide.cpio claude-p.cpio sans-reseau.cpio nmi.cpio trace.cpio \
	  tests-demarrage.txt serial.log trace.log verrous.log \
	  capture.log qemu.log ecran.png test-*.log test-*.pcap claude-p.log $(MON_TESTS)
	rm -f $(PRIVE_FICHIERS)
	rmdir $(PRIVE) 2>/dev/null || true
	rm -rf $(LINUX)
	rm -rf $(GLIBC)
	rm -rf $(SUITE)
	cd noyau && cargo clean
	cd wasm && cargo clean
	cd bonjour && cargo clean
	cd lecteur && cargo clean
	cd bonjour-tcp && cargo clean
	cd formats && cargo clean
	cd zones && cargo clean
	cd fichiers && cargo clean
	cd inet && cargo clean
	cd crypto && cargo clean
	cd roue && cargo clean

.PHONY: run texte test duree qemu-disque qemu-options debug capture gdb dump trace verrous verrous-claude-p tests-hote tests-hote-root tests-qemu claude-p jeton claude-bonjour suite clean FORCE
