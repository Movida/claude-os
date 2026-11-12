---
name: fin-d-etape
description: Clore une étape (ou une sous-étape) du projet avant le premier push et le tag etape-NN — relecture de fond, corrections repliées dans le commit qui avait introduit chaque défaut, vérification commit par commit, documentation, commandes WSL. Sert aussi, exceptionnellement, à replier des corrections dans un historique déjà poussé.
---

# Fin d'étape

Le dépôt doit se lire étape par étape, comme si tout avait été bien fait
du premier coup (voir `CLAUDE.md`, « Historique git »). Une correction trouvée
après coup ne doit donc pas rester un commit « correction de... » : elle est
repliée dans le commit qui avait introduit le défaut. C'est simple tant que
rien n'est poussé (cas A) ; c'est lourd après (cas B). D'où la règle : on
relit à fond AVANT le premier push d'une étape.

Le conteneur n'a pas de clé SSH : il ne peut ni `git fetch` ni pousser.
`origin/main` y est la dernière copie connue de GitHub, mise à jour quand
David pousse depuis WSL (même dossier `.git`). Tout push se fait par David,
avec les commandes données à la fin.

## A. Cas normal : rien n'est encore poussé

`BASE` = `origin/main` (le dernier état publié).

1. **Relecture de fond** de `git diff BASE..HEAD`, en effort élevé, fichier par
   fichier. Points propres à ce projet, à vérifier un par un :
   - **Chevauchements de zones mémoire** : pile du chargeur, tampon du noyau,
     EBDA, premier Mio, tables de pages, carte E820, .bss et pile du noyau.
     Tracer pour chaque zone son début, sa fin et son sens de croissance.
   - **Verrous et interruptions** : que se passe-t-il si une exception ou une
     IRQ arrive pendant qu'un verrou est tenu ? État de IF après chaque
     chemin ; ordre `sti; hlt` ; ordre de libération des gardes.
   - **Arrondis et débordements** : en version optimisée, Rust ne vérifie pas
     les débordements ; borner avant d'arrondir.
   - **Vrai matériel contre QEMU** : 8042 (touches pendant la configuration),
     taille de l'EBDA, BPB réécrit par les BIOS qui démarrent sur clé USB,
     délais des vieux contrôleurs.
   - **Commentaires à jour** : chaque affirmation (« l'IST protège du
     débordement ») doit être vraie AUJOURD'HUI, ou dire ce qui manque.
   - **Avertissements** de compilation, et textes affichés par l'OS sans
     accents.
   - **Cas d'erreur déclenchés volontairement**, avec un bout de code
     temporaire jamais commité : `int3`, faute de page, double faute (pile
     sur une adresse non projetée), débordement de pile (récursion infinie),
     panique au milieu d'un affichage, erreur de lecture disque, processeur
     32 bits (`-cpu qemu32`), mémoire de 128 Mio à plusieurs Gio (`-m`).
     `make debug` ou `-d int,cpu_reset -D qemu.log` montrent la chaîne des
     exceptions.
   - **Chaque chemin d'entrée dans le noyau et de sortie** (depuis
     l'étape 5 : `syscall`, interruption venue de l'anneau 3 ou 0, pile
     IST, premier départ d'un programme, `sysretq` et `iretq`) : faire un
     tableau, chemin par chemin, avec l'état de IF et d'AC (`clac` fait ?),
     la pile utilisée à chaque instruction (un instant sur la pile du
     programme ?), le privilège d'origine (`CS & 3`) et ce qu'on en décide,
     et les registres qui pourraient fuir vers le programme : généraux,
     mais aussi x87/MMX/SSE (`fninit` n'efface pas ST0-ST7) et les bases de
     FS et GS. Depuis 6j, une colonne de plus : QUEL GS est chargé à
     chaque instruction (celui du noyau, avec la zone par processeur, ou
     celui du programme : `swapgs` fait ou non), et deux lignes de plus
     pour #DB : celui d'un point d'arrêt matériel sur une donnée lue par
     `mov ss` juste avant `syscall`, qui frappe la première instruction du
     noyau, en anneau 0 avec le GS du programme (le chemin « paranoïaque »
     de interruptions.rs, qui décide d'après le signe du MSR GS_BASE,
     jamais d'après CS) ; et celui du pas à pas (TF), que `syscall` efface
     (FMASK) et qui ne frappe donc que la première instruction après
     `sysretq`, en anneau 3 : le chemin ordinaire, d'après CS, avec la
     copie de son cadre sur la pile de la tâche. Essayer chaque fois depuis un
     programme : `int n`, `icebp`, TF avant `syscall`, `mov ss` puis
     `syscall`, NMI injecté par le moniteur QEMU (`nmi`) pendant qu'il
     tourne.
   - **Le temps** : une boucle d'appels système coûteux doit, elle aussi,
     épuiser le budget de temps d'un programme. Pas de gros travail
     interruptions coupées (les tics de l'horloge se perdent).
   - **Pour une bibliothèque testée sur l'hôte** (étape 4) : faire échouer
     un test exprès pour vérifier que `make tests-hote` le signale ; faire « muter »
     le code (un décalage de un) pour vérifier qu'un contrôle le détecte
     (`cargo mutants`, un outil de l'hôte comme `wast2json`, le fait pour
     toute une bibliothèque : les modules qui survivent à beaucoup de
     mutations sont ceux que les tests vérifient mal) ;
     fuzzer décodeur et validateur avec des millions de modules corrompus,
     dans une crate temporaire du brouillon qui dépend de la bibliothèque
     par son chemin (`overflow-checks = true` dans son profil, et un
     allocateur qui mesure le pic de mémoire). Rien de cela n'est commité.
     Après une mutation, restaurer le fichier avec une date NEUVE (`cp`
     sans `-p`, ou `touch`) : `mv` et `shutil.move` gardent l'ancienne
     date, plus vieille que le binaire compilé avec la mutation, et cargo
     ne recompile pas (on teste alors encore le code muté).
2. **Présenter les constats à David** (ce qui est faux, pourquoi, la
   correction proposée), puis corriger.
3. **Chaque correction devient un `fixup` du commit fautif** :
   - trouver le commit : `git log -L <début>,<fin>:<fichier>` ou `git blame` ;
   - `git commit --fixup=<sha>` ; si la correction touche deux commits,
     `git add -p` pour la couper en deux fixups ;
   - `git commit --fixup=amend:<sha>` quand le message du commit doit aussi
     changer pour décrire le résultat final.
   - Ne jamais `git commit -a` : la copie de travail de David peut contenir des
     modifications à lui (le `.devcontainer`, par exemple).
4. **Replier** :
   ```sh
   git branch sauvegarde-fin-etape-NN
   GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash --autostash BASE
   ```
   (`GIT_SEQUENCE_EDITOR=:` accepte la liste préparée par `--autosquash` sans
   ouvrir d'éditeur.) En cas de conflit : le résoudre pour que le commit ait
   l'état qu'il AURAIT dû avoir, `git add`, `GIT_EDITOR=true git rebase --continue`.
5. **Vérifier** :
   ```sh
   sh .claude/skills/fin-d-etape/verifier-historique.sh BASE sauvegarde-fin-etape-NN
   git range-diff BASE sauvegarde-fin-etape-NN HEAD
   ```
   Le script construit et teste chaque commit dans un worktree temporaire,
   puis compare l'arbre final à la sauvegarde : il doit être identique (une
   réécriture ne change que l'historique). `range-diff` montre, commit par
   commit, ce que chaque fixup a changé.
6. **Documenter** : `CLAUDE.md` (feuille de route), `HISTORIQUE.md` (ce que
   l'étape a fait ; « Reste à faire » : chaque dette avec l'étape qui la
   remboursera, ou ce qui la déclenchera, et les écarts voulus avec Linux
   à part), `README.md` (où en est le projet, le tableau des étapes : il
   s'était arrêté à 6d sans que personne le voie), dans un commit
   « Projet : etape NN terminee ... ».
7. **Supprimer** les branches de travail et la sauvegarde devenues inutiles.
8. **Commandes pour David**, depuis WSL, dans le dépôt :
   ```sh
   git push origin main
   git tag -a etape-NN -m "Etape NN verifiee dans QEMU"
   git push origin etape-NN
   ```
   (Le tag se pose depuis la VM de David : le proxy de la session cloud
   refuse les tags.)
9. **Regarder la CI**, une fois le push fait. Son état se lit sans jeton :
   `curl -s https://api.github.com/repos/Movida/claude-os/actions/runs?per_page=2`.
   Ses journaux demandent les droits d'administrateur, mais ses échecs sont
   dans les annotations, sans jeton : `.../check-runs/<id du job>/annotations`
   (l'id : `.../actions/runs/<run>/jobs`). Le détail complet, David le copie
   depuis la page du run (roue dentée, « View raw logs »). Elle est restée
   rouge onze jours sans que personne le voie. Et AVANT le push : passer
   sous le Linux de référence, celui de la CI depuis les soldes de novembre
   2026 (6.18.33, dans une machine virtuelle sur le système de fichiers du
   conteneur), les programmes de test sur l'hôte de l'étape, puisque la CI
   s'arrête au premier échec (un push par écart) :
   `.devcontainer/linux-de-reference.sh bash
   .claude/skills/fin-d-etape/programmes-sur-l-hote.sh ETAPE` (la partie
   « programmes » de `make -n tests-hote`, une commande à la fois par
   `sh -c` comme make, sans les lignes `cd ...` de cargo, qui ne dépendent
   pas du noyau et prennent des heures sous TCG ; un script à soi va dans
   HOME ou le dépôt : la machine voit le /tmp de l'hôte, mais ce qu'elle y
   écrit reste chez elle). Jamais pendant une autre vérification : la
   machine compte parmi les deux QEMU au plus du conteneur (2 Gio par
   défaut). La CI, elle, y passe tout `verifier.sh`, sous KVM.

## B. Exceptionnel : replier dans un historique déjà poussé

Seulement tant que personne d'autre n'a récupéré le dépôt (voir `CLAUDE.md`) ;
sinon, de nouveaux commits de correction. Mêmes étapes que A, avec en plus :

- `BASE` = le parent du plus ancien commit à modifier.
- Les modifications non commitées de David vont dans le commit qui leur
  correspond (lui demander ce qu'elles sont, ne rien jeter).
- Quand les fixups se chevauchent trop pour `rebase --autosquash` (conflits à
  chaque commit), reconstruire chaque commit avec la plomberie git : partir
  de l'arbre du commit d'origine (`git read-tree` dans un index temporaire,
  `GIT_INDEX_FILE`), y écrire les fichiers corrigés (`git hash-object -w`,
  `git update-index --cacheinfo`), puis `git write-tree` et `git commit-tree`
  avec l'auteur, le committer et les dates d'origine (`GIT_AUTHOR_*`,
  `GIT_COMMITTER_*`, lus par `git log -1 --format=... --date=raw`). Sauvegarde
  d'abord, `git reset <nouveau-main>` (sans --hard) à la fin.
- **Tags annotés** recréés sur le commit équivalent, avec le même message,
  le même auteur et la même date :
  ```sh
  # Pour chaque tag : nom, ancien commit, nouveau commit.
  recreer_tag() {
      test "$(git rev-parse "$1^{commit}")" = "$(git rev-parse "$2")" || { echo "$1 : tag inattendu"; return 1; }
      GIT_COMMITTER_NAME="$(git tag -l --format='%(taggername)' "$1")" \
      GIT_COMMITTER_EMAIL="$(git tag -l --format='%(taggeremail:trim)' "$1")" \
      GIT_COMMITTER_DATE="$(git for-each-ref --format='%(taggerdate:raw)' "refs/tags/$1")" \
          git tag -f -a -m "$(git tag -l --format='%(contents)' "$1")" "$1" "$3"
  }
  recreer_tag etape-03 444a94b 3dffb19
  ```
- **Commandes pour David**, avec un bail EXPLICITE :
  ```sh
  git fetch origin
  git rev-parse origin/main         # doit valoir <ANCIEN> ; sinon, s'arrêter
  git push --force-with-lease=main:<ANCIEN> origin main
  git push --force origin etape-01 etape-02a ...   # les tags recréés
  git branch -D sauvegarde-...                    # une fois tout en ligne
  ```
  où `<ANCIEN>` est le hash COMPLET de l'ancien `origin/main`, noté dans le
  conteneur avant la réécriture. Pourquoi pas `--force-with-lease` tout court :
  sans valeur, git compare l'état distant à `origin/main`... que le
  `git fetch` juste avant vient de mettre à jour. Le bail ne protège alors plus
  de rien : un commit poussé entre-temps d'ailleurs serait écrasé en silence.
- Prévenir David : tout autre clone (une autre machine) devra être re-cloné,
  ou `git fetch` puis `git reset --hard origin/main`.

## Pièges déjà rencontrés (24 octobre 2026)

- Pas de clé SSH dans le conteneur : ni fetch ni push, tout passe par WSL.
- « Etape 02a : passage en mode protege, plomberie » échoue à `verifier.sh`
  par construction (le mode protégé ne marche qu'au commit suivant) : le
  script le signale comme échec attendu.
- Un commentaire qui raconte une correction (« Avant, la pile partait de
  0x90000... ») n'a plus de sens une fois la correction repliée : le
  reformuler pour décrire le choix (« À l'étape 2b, ... ; ici, ... »).
- `git commit -a` a deux fois embarqué les modifications du `.devcontainer`
  de David : toujours nommer les fichiers à commiter.
- Ne pas utiliser `RUSTFLAGS="-D warnings"` : la variable d'environnement
  remplace les `rustflags` de `.cargo/config.toml` (dont
  `relocation-model=static`), et on testerait un autre noyau. Détecter les
  avertissements en cherchant `^warning` dans la sortie de make ou cargo.
- `cargo test | tee ... | grep` rend le code de sortie de `grep` : un test
  en échec passait inaperçu, et la CI serait restée verte. Toute recette de
  Makefile avec un tuyau : `SHELL = /bin/bash` et `.SHELLFLAGS = -o pipefail -c`.
- Un relecteur indépendant (un agent lancé sans nos conclusions, avec le
  code et la spécification) a trouvé à l'étape 4 ce que la suite officielle
  et notre fuzzing ne voyaient pas : une réservation mémoire 64 fois trop
  grosse, un type de bloc mal formé accepté. Vérifier chacun de ses constats
  avant de corriger.
- Pas de `rm -rf "$VARIABLE"` dans les commandes : la protection de Claude Code
  les bloque ; utiliser `git worktree remove` et des chemins écrits en entier.

## Pièges rencontrés à l'étape 5 (24 octobre 2026)

- Ne jamais enchaîner `verifier.sh ... ; git commit` dans une même commande
  sans lire le résultat : un commit est parti alors que `tests-qemu`
  échouait. Commiter seulement après avoir lu « verifier : 0 ».
- Une ligne attendue ne doit pas contenir de valeur qui dépend d'autre chose
  que de ce qu'elle teste (la valeur de RSP dans un message de faute :
  elle a changé quand la pile initiale s'est remplie). Garder le début et
  la fin du message.
- Un test doit vérifier la RAISON d'un refus, pas seulement qu'il y a refus :
  un cas « page partagée avec le segment précédent » était en fait refusé
  parce que le segment sortait du fichier.
- QEMU sans accélération (TCG) n'est pas un vrai processeur :
  `icebp` y est une instruction invalide (#UD, pas #DB) ; après `mov ss`, un
  pas-à-pas y tombe avant l'instruction suivante au lieu d'après ; et les
  interruptions n'y sont délivrées qu'entre deux blocs traduits : une
  fenêtre `sti ... cli` de quelques instructions peut ne jamais en laisser
  passer. Écrire les tests pour qu'ils acceptent les deux comportements,
  le dire en commentaire, et comparer avec le même programme sous Linux sur
  l'hôte.
- Provoquer une erreur de lecture disque : `-drive
  driver=blkdebug,config=...,image.driver=file,image.filename=boot.bin,if=ide`
  avec une règle `[inject-error]` (`event = "none"`, `iotype = "read"`,
  `sector`, `once`). Injecter un NMI : `nmi` sur la socket du moniteur.
- Pendant `rebase --autosquash`, chaque fixup d'un fichier que les commits
  suivants modifient aussi provoque des conflits en chaîne. Pour un fichier
  que plus aucun commit ne touche après le fixup, prendre directement sa
  version finale dans la sauvegarde (`git show sauvegarde-...:fichier`),
  moins ce que les fixups restants ajouteront. Pour les motifs qui
  reviennent (une liste de dépendances, une ligne de tests), un petit script
  de résolution dans le brouillon. Construire et tester l'état de chaque
  commit résolu avant `rebase --continue`.
- Pendant le rebase, les fichiers construits par les commits suivants
  apparaissent comme non suivis (le `.gitignore` de l'époque ne les connaît
  pas encore) : ne jamais `git add -A`, nommer les fichiers.

## Pièges rencontrés en 6a (25 octobre 2026)

- **La faute servie.** CR2 se lit en tout premier. Une faute du noyau sur
  une adresse de programme n'est servie que dans une copie de la table
  d'exceptions, avec AC à 1 si SMAP est actif (sinon le test de SMAP du
  démarrage, sans `stac`, serait servi sans fin), et un processus en
  cours. Le verrou du processus est rendu AVANT `tache::arreter` ou
  `terminer`, qui ne reviennent pas. La page de zéros n'est jamais rendue
  (`pages::liberer` paniquerait) ; une table rendue l'est après le vidage
  complet du TLB (caches des tables, Intel vol. 3A 4.10.3).
- **Les petites allocations du tas du noyau gardent leurs pages** :
  une structure par programme qui passe par les classes du tas fait
  mentir « memoire rendue » au premier programme qui l'agrandit. La
  carte des zones prend donc d'emblée une page entière.
- **Un test sur l'hôte ne doit dépendre d'aucun réglage** : le
  devcontainer a `vm.overcommit_memory = 1` (« toujours »), un conteneur
  `mmap_min_addr = 4096`. Les cas qui en dépendent restent dans QEMU.
- **Vérifier une affirmation du plan contre Linux avant de l'écrire en
  test** : le plan voulait 300 Mio accordés d'un coup sur 128 Mio, ce que
  Linux refuse ; il disait l'adresse suggérée arrondie au-dessus, elle
  l'est au-dessous. Une sonde C sur l'hôte tranche en une minute.
- **`pkill -f motif` tue aussi le shell qui le lance** (sa ligne de
  commande contient le motif) : viser le numéro de processus
  (`pgrep -a`, puis `kill`). Un QEMU resté en marche garde le verrou
  d'écriture de son image : les QEMU suivants échouent en silence.
  Démarrer une COPIE de l'image pour les essais à la main.
- **Le temps du démarrage** : le chargeur lit l'archive par le BIOS, un
  quart de seconde par Mio sous QEMU ; `verifier.sh` laisse 2 s. Mesurer
  (une ligne datée par message du port série) avant d'ajouter un gros
  programme à l'archive ordinaire.

## Pièges rencontrés en 6b (25 octobre 2026)

- **Les relecteurs meurent avec le tour qui les a lancés** : un message de
  David arrivé pendant la relecture (en Remote Control) a interrompu les
  trois agents en arrière-plan, sans rien dire. Leur demander d'écrire
  chaque constat dans un fichier de leur brouillon dès qu'il est vérifié,
  et vérifier qu'ils tournent encore (la date de leur journal) avant de
  dire qu'ils travaillent.
- **La signature des commits passe par l'agent SSH de Windows**, que VS
  Code fait suivre au conteneur (`/tmp/vscode-ssh-auth-*.sock`). Après un
  changement du code Windows Hello, ou un redémarrage, l'agent peut ne plus
  répondre (une minute d'attente, puis « communication with agent
  failed ») ou ne plus être suivi du tout. Essayer une signature
  (`ssh-keygen -Y sign`) AVANT de lancer un rebase ; la prise la plus
  récente est la bonne (`ls -t`), à passer dans SSH_AUTH_SOCK.
- **Un rebase interrompu se reprend** : son état est dans `.git`, et
  survit au redémarrage du conteneur. Le brouillon de la session, lui, peut
  disparaître : y garder des copies, pas l'unique version d'un fichier.
- **Un fixup qui ajoute un test dans un fichier que des commits suivants
  modifient** : vérifier que le test compile à l'état du commit visé (une
  fonction, un `#include`, un appel système qui n'existent qu'après).
  Construire le programme de test à chaque commit résolu, pas seulement
  le noyau.
- **`ulimit -v` fausse les tests de la mémoire** sur l'hôte
  (`linux/memoire` réserve 64 Gio) : le garder pour cargo et les sondes, pas
  pour `make tests-hote` (le plafond du conteneur suffit).
- **Un terminal n'est pas un fichier** : une faute au milieu du tampon
  rend ce qui a été écrit pour un fichier, mais EFAULT pour une console
  (`iterate_tty_write` copie chaque morceau en entier). Un test de l'étape 5
  l'a rappelé.

## Pièges rencontrés en 6c (25 octobre 2026)

- **Trois relecteurs en même temps saturent la machine** (une charge de 16
  sur 12 cœurs) : le démarrage passe de 3 à 15 s, et les délais fixes
  (`DUREE`, les 2 s par défaut de `verifier.sh`) font échouer des commits
  justes dans `verifier-historique.sh`. Relancer seul un commit en échec
  avant d'y croire ; lancer la vérification de l'historique quand les
  relecteurs ont fini.
- **Un test qui écrit « ok » quoi qu'il arrive ne prouve rien** :
  `interp-milieu` affichait sa ligne même sans ld-linux, et « la
  bibliothèque n'est plus projetée » ne demandait qu'à ld-linux (dladdr).
  Chaque vérification doit passer par ce que fait le NOYAU (AT_BASE dans
  le vecteur auxiliaire, `madvise` qui rend ENOMEM), et doit échouer
  quand on casse ce qu'elle vérifie : l'essayer sur une copie.
- **make décide par les dates, dpkg garde celle de la construction du
  paquet** : un fichier de la machine mis à jour par apt peut paraître
  plus ancien que notre copie. Copier ce qui vient du système d'après une
  empreinte du contenu, recalculée à chaque construction.
- **Une vérification de version doit porter sur ce qui compte** : le
  format du cache de ld-linux dépend de 2.39, pas de la révision d'Ubuntu
  (2.39-0ubuntu8.9), et `ldconfig` est dans un autre paquet que libc6.
- **Replier des fixups dans des commits que les suivants réécrivent** :
  pour un commit dont les fichiers ne bougent plus ensuite, prendre la
  version de la sauvegarde ; sinon, la sauvegarde moins le diff des
  commits suivants (`diff -u` de leurs versions, puis `patch -R` sur la
  sauvegarde), et finir à la main les morceaux refusés. Construire et
  tester chaque état résolu ; l'arbre final doit être celui de la
  sauvegarde (`git diff sauvegarde HEAD` vide).

## Pièges rencontrés en 6d (26 octobre 2026)

- **Les notes de relecture ont disparu avec la reconstruction du
  devcontainer** : `~/.cache` et `/tmp` sont effacés, `~/.claude/projects/`
  survit. Y garder les notes de travail
  (`~/.claude/projects/-workspaces-claude-os/relecture-NN/`). Si elles sont
  perdues, les rapports des relecteurs sont dans les journaux de la
  session : `~/.claude/projects/-workspaces-claude-os/<session>/subagents/*.jsonl`
  (l'outil `SubagentHandback` porte le rapport final, les `Write` et les
  `cat >>` les notes au fil de l'eau).
- **Un test du démarrage qui dépend de la disposition de la mémoire** :
  « rendu puis redonne : ECHEC » est apparu sans toucher à l'allocateur,
  parce que le noyau avait grandi et que trois cadres tombaient à cheval
  sur deux mots de la carte de bits. Chercher la cause avant d'accuser la
  dernière modification.
- **Une correction pour du code introduit avant d'être observable** (Vue::refus
  en 8952269, quand rien n'était encore monté) doit être écrite pour l'API
  de ce commit-là (refus rendait `Erreur`, pas `Result`). Avec beaucoup de
  fichiers communs, un rebase en `edit` sur chaque commit est plus sûr que
  des fixups : pour un fichier qu'aucun commit suivant ne touche, prendre
  sa version finale (`git checkout corrections -- fichier`) ; sinon,
  appliquer à la main la part de la correction, construire et tester
  avant de continuer. Garder l'état final sur une branche, et comparer
  l'arbre à la fin.
- **errno se lit tout de suite** : `int r = erreur(syscall(...))` ; plusieurs
  appels puis `erreur(r1) && erreur(r2)` lisent tous le dernier errno.
- **Le conteneur fausse certaines mesures** : `/proc/sys` y est un montage à
  part (un rename dedans rend EXDEV) et `/sys` est en lecture seule ; ne pas
  en faire des lignes de test qui tournent aussi sur l'hôte.
- **Une borne de temps mesurée des deux côtés** : sous Linux, RLIMIT_CPU
  tombe à 0,96 s de CLOCK_PROCESS_CPUTIME_ID, pas après 1 s ; une borne
  écrite d'après la théorie (1,0 à 1,1 s) échouait sur l'hôte.
- **Attendre une ligne plutôt qu'un délai fixe** pour un QEMU qui ne
  s'éteint pas (`attendre` dans le Makefile de 6d) : plus rapide sur une
  machine tranquille, et plus sûr sur une machine chargée.

## Pièges rencontrés en 6e (31 octobre 2026)

- **La signature peut tomber en panne pour des jours** : quand l'agent de
  1Password ne signe plus dans le conteneur, garder chaque commit en patch
  (`git diff` contre un index temporaire, `GIT_INDEX_FILE`, plus le message)
  dans `.git/attente-signature/` ; David les crée depuis WSL, dans l'ordre
  (`git apply --cached cNN.patch && git commit -F cNN.txt`). Ne jamais
  commiter sans signature.
- **Le `.git` est partagé avec WSL** : un `git pull --rebase` de David
  pendant le travail réécrit la branche sous nos pieds (vu : origin/main
  avait reçu une PR). Avant un repli, lui demander de ne plus toucher à la
  branche, et repartir de `origin/main` tel qu'il est alors.
- **Un test de concurrence doit mordre** : le vérifier par une mutation
  (retirer ce qu'il protège). Sous QEMU sans accélération, une fenêtre
  d'interruptions de quelques instructions ne laisse presque jamais passer
  la préemption : un test qui compte sur elle ne prouve rien (« lignes ») ;
  un test qui garde ouvertes les poignées en jeu, et les change d'un coup
  (dup2), mord (« courses »).
- **« memoire rendue » faux par moments** : chercher ce qui est rendu en
  retard (l'écart s'affiche, en pages : -N puis +N au programme suivant),
  pas une fuite. En 6e : un processus devenu zombie avant que la pile d'un
  de ses fils ne soit rendue.
- **Un échec isolé de `verifier-historique.sh`** (un commit, puis OK quand
  on le relance seul) : la machine chargée ; le journal de l'échec est
  désormais gardé, le lire avant de conclure.

## Pièges rencontrés en 6f (31 octobre 2026)

- **Replier dans des commits en attente de signature** (des patchs, pas
  de commits) : un petit dépôt git à part, dans le brouillon, dont le
  premier commit est l'état final de l'étape ; une correction par commit,
  son sujet commençant par le commit visé (« c13 : ... »), remis dans
  l'ordre des commits visés (`git cherry-pick`). Puis chaque instantané
  refait, fichier par fichier, par `git merge-file` (le nôtre : l'ancien
  instantané ; la base et le leur : avant et après la correction), les
  conflits écrits à la main une fois pour chaque instantané qui les a.
  Le dernier instantané doit être l'état final ; `git range-diff` des
  deux chaînes (des commits faits par `git commit-tree`, dans ce dépôt à
  part) montre ce que chaque repli a changé.
- **Une correction ne se replie que vraie au commit visé** : un
  commentaire qui ne devient vrai qu'avec un commit suivant (« task et
  fd ») se coupe en deux corrections, une par commit.
- **Un test qui ne couvre que le cas difficile laisse passer le cas
  simple** : `/proc/self/fd/N` n'était ouvert qu'après l'effacement du
  fichier, et ouvrir celui d'un fichier qui a son nom (ou `/dev/stdout`)
  arrêtait le noyau. Pour chaque chemin nouveau, essayer aussi l'usage le
  plus banal.
- **Un relecteur se trompe parfois sur le remède** : « (deleted) d'après
  le nom ouvert » aurait fait dire « (deleted) » d'un fichier simplement
  renommé, faute de dentry. Vérifier ce que la correction proposée casse
  avant de l'appliquer, et écrire l'écart quand le bon remède dépasse
  l'étape.
- **Un test d'ordonnancement peut ne mordre que chez nous** : le signal
  qui réveille sigsuspend pris par un autre fil arrive vingt fois sur
  vingt dans notre noyau, jamais sur l'hôte (Linux ne prévient que le fil
  choisi). Le test l'affiche, ne l'exige pas sur l'hôte, et une mutation
  prouve qu'il mord dans QEMU.

## Pièges rencontrés en 6g (1er novembre 2026)

- **Un `edit` qui conflicte ne s'arrête qu'une fois** : dans
  `rebase -i`, un commit marqué `edit` dont l'application conflicte
  s'arrête sur le conflit ; après `git add` et `rebase --continue`, git
  le commite avec son ancien message et passe au suivant, sans l'arrêt
  promis. Donner le nouveau message à l'arrêt du conflit (`git commit
  -F`, puis `rebase --continue` ; la date d'auteur devient alors celle du
  jour), ou après coup par la plomberie.
- **Une phrase que chaque commit allonge** (l'en-tête du Makefile,
  « Sous-étape 6g : ... ») : complétée au bout de sa ligne sans la
  refaire, elle a fini à 114 colonnes en six commits. Reprise par la
  plomberie de la section B, sans rebase : pour chaque commit, le fichier
  du commit d'origine passé dans une fonction pure (un script Python du
  brouillon : la phrase de l'étape remise en forme par `textwrap`, avec
  des espaces insécables le temps de couper, pour qu'aucune ligne ne
  commence par « : » ou « ; »), l'arbre gardé pour le reste : aucun
  conflit, quel que soit le nombre de commits.
- **Linux livre ce qui part par `lo` dans l'appel qui envoie** (le
  softirq exécuté à la sortie de `__dev_queue_xmit`) : un test qui
  attendait « que lo ait tout livré » (par un datagramme témoin) cachait
  que, chez nous, le datagramme n'était pas encore là au retour de
  `sendto`. Essayer d'abord sur l'hôte le cas sans attente
  (`recv(MSG_DONTWAIT)` juste après `sendto`).
- **Le devcontainer filtre des appels du réseau que la CI laisse
  passer** : le seccomp de Docker (`socket(46, ...)` : EPERM),
  `ping_group_range` et `ip_unprivileged_port_start` réglés par Docker,
  SELinux compilé dans le noyau de WSL. Aucun test sur l'hôte ne doit en
  dépendre (les sockets de ping : seulement si l'hôte les permet).
- **La glibc abandonne un essai DNS** sur une réponse plus courte qu'un
  en-tête, et recommence avec une autre socket : un test qui ment au
  résolveur ne le fait qu'au premier essai, et compte les questions
  (mesuré sur l'hôte).
- **Le classifieur du mode automatique refuse** de tuer un QEMU par
  motif, et de créer un document dans une application connectée sans
  qu'on l'ait demandé : lancer chaque QEMU sous `timeout` et l'attendre ;
  écrire les rapports en `.md`, envoyés comme fichiers.
- **Une boucle `while read ... < liste` qui signe peut s'arrêter sans
  rien dire** : le programme de signature de WSL (celui de 1Password) a
  lu l'entrée standard de la boucle, et donc les lignes qui restaient.
  Seul c00 a été créé, puis poussé et tagué, sans aucun message
  d'arrêt. Reproduit avec un signataire qui lit son entrée. Lire la
  liste par un autre descripteur (`while read -r k <&3; do ... done 3<
  liste`), et donner `</dev/null` aux commandes de la boucle.

## Pièges rencontrés pendant la relecture globale (2 novembre 2026)

- **Un auto-test du démarrage qui ne peut pas échouer** : `verifier.sh`
  cherchait chaque ligne attendue n'importe où, jamais l'absence d'un
  « ECHEC » ; une vérification dont la ligne attendue était aussi
  contenue dans 33 autres lignes passait toujours. Pour chaque ligne
  attendue neuve, vérifier qu'elle ne se trouve pas déjà ailleurs dans
  le journal (`grep -c`), et faire échouer exprès ce qu'elle vérifie.
- **clippy ne reconnaît que « SAFETY: »** (sans l'espace du français)
  pour `undocumented_unsafe_blocks` ; et `rustup` ajoute tout seul un
  composant listé dans le `rust-toolchain.toml` d'une étape (clippy),
  même si la version est déjà installée (vérifié avec rustup 1.29).
- **Couper un travail déjà fait en plusieurs commits** : appliquer à
  l'index des morceaux de `git diff -U0` (`git apply --cached
  --unidiff-zero`) les a placés de travers là où deux morceaux se
  touchaient. Reconstruire plutôt chaque fichier du commit (le texte
  ajouté par les morceaux à garder pour plus tard, remplacé par l'ancien),
  et comparer l'arbre obtenu à la copie qui a été vérifiée (`cmp`).
- **Deux fils dans le même conteneur** : travailler dans un clone à part
  (le `.git` partagé avec WSL ne doit pas changer de branche sous l'autre
  fil), vérifier une copie de l'arbre à commiter (`git checkout-index -a
  --prefix=...`, puis `VERIF_RACINE`) pendant qu'on avance dans le clone,
  et ne lancer qu'un QEMU à la fois.

## Pièges rencontrés en 6h (3 novembre 2026)

- **48 corrections dans des commits que les suivants réécrivent** (2 600
  lignes, dont la moitié dans le commit des connexions TCP, que la
  fiabilité et le débit avaient transformé ensuite) : ni `rebase
  --autosquash`, ni un fixup par correction. Ce qui a marché, par la
  plomberie, dans un dossier de notes (pas le brouillon) :
  - les COUCHES : l'arbre final d'origine (F), plus les corrections de
    chaque commit visé, dans l'ordre (F1, F2...), la dernière égale à
    l'arbre corrigé et vérifié ; chaque couche écrite par morceaux du
    `git diff -U0` (une table « morceau → commit visé ») et des éditions
    qui retirent d'une couche ce qui n'arrive qu'avec un commit plus
    tardif ;
  - les INSTANTANÉS : pour chaque commit d'origine, la fusion à trois
    (`git merge-file`) de son propre changement dans l'instantané corrigé
    précédent, puis celle de sa couche (base Fk-1, le leur Fk) ; quand la
    première conflicte, essayer la fusion « directe » (l'origine du commit
    plus toutes les couches d'avant), souvent propre quand le commit est
    proche de la fin ;
  - chaque conflit résolu à la main, une fois, dans un fichier rangé par
    commit et par étape de fusion, avec le résultat automatique qu'il
    remplace : un résultat qui change ensuite (une couche corrigée) le
    signale, au lieu d'appliquer en silence une résolution périmée ;
  - le dernier instantané doit être l'arbre corrigé, octet pour octet ;
    puis chaque commit construit (clippy compris), testé, et vérifié dans
    QEMU, et les commits faits par `commit-tree`, sans signer, re-signés
    d'un coup à la fin.
- **Une correction se replie sous la forme qu'avait le code alors** :
  `accept4` en TCP seul dans le commit des connexions, puis TCP et AF_UNIX,
  puis `socket::fermer` quand WASI l'apporte ; `fatale` avant que la
  fiabilité ne le renomme `injoignable`. Et ce qui MANQUAIT n'est pas un
  défaut : une correction qui demande une machinerie plus tardive (l'heure
  dans la `Tcb`, pour limiter les ACK) va dans le commit qui l'apporte.
  Noter chaque reciblage, pour les messages.
- **Un commentaire corrigé doit être vrai au commit visé** : « `Arc::new`
  ne sait pas échouer » était vrai au commit des connexions, et n'est
  devenu faux qu'avec le `Arc` faillible de la relecture globale ; c'est
  là que se replie sa nouvelle raison.
- **Les tests ajoutés par la relecture vont avec les tests de leur
  commit**, pas à la fin du fichier : sinon chaque repli conflicte en fin
  de fichier, et l'arbre final diffère de celui qui a été vérifié. Ranger
  d'abord l'arbre corrigé (et le revérifier), puis replier ; couper un
  test qui mêle deux commits (un `seuil_et_faute` devient `faute` et
  `seuil`), et déplacer un utilitaire de test vers le commit de son
  premier usage.
- **Vérifier une chaîne repliée** : `verifier-historique.sh` relance toutes
  les étapes à chaque commit (des heures pour 22 commits : les `claude -p`
  de 6f, 6g et 6h à chacun). Quand seul le dossier de l'étape change
  (`git diff --name-only` contre `origin/main`), vérifier cette étape
  seule, en deux voies parallèles (deux worktrees, au plus deux QEMU de
  2 Gio), et sauter les commits qui ne la changent pas.
- **La signature par 1Password** demande l'accord de David, et cet accord
  ne dure que quelques minutes : sa notification arrive dans le systray de
  Windows (pas toujours visible), et un redémarrage de 1Password l'a
  réparée quand elle ne venait plus. Ses messages n'arrivent qu'à la fin
  d'un tour : si la signature échoue, finir le tour pour lire sa réponse.

## Pièges rencontrés en finissant 6h (6 novembre 2026)

- **`cargo mutants` sur un gros fichier** (1 467 mutants, 15 s chacun) :
  `--shard k/n` coupe en parts de moins de 2 h, la limite d'une commande en
  arrière-plan. Une part coupée ne le dit pas dans ses listes : comparer
  `mutants.json` à caught, missed, timeout et unviable. Pour repasser
  seulement les survivants, sur les seuls tests internes (quelques secondes
  au lieu d'heures) : `--iterate`, et un `caught.txt` écrit à la main qui
  contient toute la liste (`--list`) sauf eux. Un mutant s'y reconnaît à son
  fichier, sa ligne et sa colonne : une ligne ajoutée en tête du fichier les
  décale tous.
- **Un mutant équivalent, c'est parfois du code qui ne sert à rien** : à
  lire comme tel, avant de le classer. Noter pour chacun pourquoi il est
  équivalent, et dire que ce n'est prouvé que par la lecture.
- **Un instantané par `git add -A` prend tout ce qui traîne** : deux
  binaires compilés à la main par un relecteur (`linux/tcp`, `linux/unix`)
  sont entrés ainsi dans l'arbre à replier. Relire la liste des fichiers
  nouveaux (`git status --short | grep '^??'`) avant chaque instantané.
- **Le fil qui reprend** repart d'un arbre sauvé, pas de sa mémoire :
  l'arbre en commit de plomberie sur une branche locale (jamais poussée),
  puis `git restore --source=<arbre> --worktree -- .` dans le worktree du
  nouveau fil, et une comparaison `diff -rq` avec l'ancien, qui reste en
  lecture seule jusqu'au tag.
- **Un test sur l'hôte ne suit pas que le noyau, mais aussi le processeur** :
  `0x7ffffffff000` n'est la dernière page qu'avec quatre niveaux de tables. Sur
  une machine LA57, Linux y projette sans rien dire. Ces différences se
  reproduisent sans la machine : le vrai Linux sous QEMU, avec `-cpu qemu64,+la57`.
- **Le noyau de la CI n'est pas le nôtre, et il change** : Linux 7.0-azure en
  novembre 2026, dans les notes de chaque image (releases de
  `actions/runner-images`, « Kernel Version »). `make` s'arrête au premier
  échec : un push par écart prendrait des heures. Son paquet exact
  (`apt-get download linux-image-unsigned-...`), sous QEMU avec `-cpu max` et
  une carte virtio, un `/init` statique qui lance la liste de `tests-hote` sans
  s'arrêter, montre tout d'un coup. Pour ressembler à la CI : l'utilisateur 1000,
  les fichiers à lui, la sortie dans un tube qu'il a créé, /tmp sur la même
  partition que la racine, un /etc/hosts.
- **Le témoin n'imite pas tout** : sous `/init`, rien n'est hérité, et le cache
  des pages est plein. Deux conditions de plus, à poser avant `verifier.sh` :
  `exec 300</dev/null` (la table de descripteurs vient des ancêtres), et
  `dd if=PROGRAMME iflag=nocache count=0` après un `sync` (un programme absent
  du cache prend des fautes majeures). `RES_OPTIONS=edns0` imite le
  `/etc/resolv.conf` d'une machine sous systemd-resolved.
- **Une fonction entre le test et `errno`** l'écrase : `access(...) && errno ==
  ENOMEM` lisait ENOENT. Garder `errno` dans une variable d'abord.

## Pièges rencontrés en 6i (8 novembre 2026)

- **Les conflits d'adjacence** : `git merge-file` déclare un conflit dès que
  les deux côtés changent des lignes VOISINES. Dans un repli par couches,
  c'est le cas ordinaire : une correction insère une ligne juste à côté de
  lignes qu'un commit plus tardif ajoutera (une règle du Makefile, une ligne
  attendue, un programme de `/etc/demarrage`). Un petit résolveur
  (`relecture-6i/repli/tolerante.py`) les tranche : dans chaque bloc, les
  régions changées de chaque côté (difflib) ; si elles ne se recouvrent pas,
  les deux s'appliquent ; deux insertions au même point prennent l'ordre de
  l'arbre final ; une même ligne changée des deux côtés (une liste de
  dépendances) se fusionne mot à mot. Chaque bloc tranché est noté, pour la
  relecture. En 6i : près de quarante blocs tranchés seuls, cinq à la main.
- **Les nombres qui se déduisent d'autres fichiers** (dans `attendu.txt` :
  les comptes de l'archive, le nombre de commandes du lanceur, les lignes
  d'un groupe) conflictent à chaque commit : les masquer pendant les
  fusions, puis les recalculer pour chaque instantané (la valeur d'origine du
  commit, plus ce que les corrections changent dans `archive.txt` et dans le
  lanceur), après avoir vérifié que la règle retrouve l'origine elle-même.
- **Un commit « Reste » neuf** n'a pas d'origine : son arbre de départ est
  celui du commit qui le précède, et il n'apporte que sa couche. Le placer
  avant le premier commit qui en a besoin.
- **`main` a avancé pendant l'étape** (deux commits d'Outillage, dans
  `.devcontainer`) : la chaîne repliée part du nouveau `main`, chaque arbre
  prenant ses fichiers, après avoir vérifié que les deux ne touchent pas les
  mêmes.
- **Replier, c'est relire chaque correction sous sa forme d'alors** : en
  écrivant la forme sans inotify d'une correction faite avec lui, un
  paramètre toujours vrai et un résultat jamais lu sont apparus dans l'arbre
  corrigé, qu'aucune relecture n'avait vus. Puis chercher les anachronismes :
  un mot d'un commit plus tardif (inotify, sendfile, setuid) apparu par le
  repli dans un commit plus ancien, en comparant chaque instantané à
  l'origine du même commit (`relecture-6i/repli/anachronismes.py`) ; un test
  ajouté dans le même morceau que celui d'un commit voisin part avec lui, et
  ne se voit qu'à `make tests-hote` (construire chaque instantané ne suffit
  pas).
- **Deux voies de vérification en parallèle se gênent** : `tests-hote-root`
  (`linux/pmtu`) change les routes de l'espace réseau de la machine, et deux
  à la fois échouent l'un par l'autre ; et la charge des deux fait dépasser
  à un démarrage la limite de `DUREE`, qui doit être mesurée seul (une ligne
  datée par message du port série) à chaque commit qui allonge le
  démarrage. Relancer seul un commit en échec avant d'y croire.
- **« memoire rendue » d'un groupe voit les places qui doublent** : la liste
  d'un dossier du tmpfs (un `Vec`) qui grandit pendant le groupe et ne
  rétrécissait jamais, le chemin d'un `cd` que garde le lanceur, comptent
  comme une page non rendue, sans fuite. Et un groupe qui passe « par
  chance de place » : un fichier de plus dans l'archive (`/tmp/prog`) a
  montré que celui de `claude -p` ne rendait sa mémoire que parce que ce
  que claude laissait dans `/tmp` tenait dans la place de la liste. Un noyau instrumenté, jetable (une
  copie dans le brouillon, jamais commitée), qui note chaque page prise et
  rendue avec son appelant, les montre en une passe.
- **Ce qu'un programme fait selon le moment** ne va pas dans un fichier
  attendu : `claude -p` efface la sonde de sa surveillance des fichiers si
  son essai, en tâche de fond, finit avant lui ; sous Linux, plus rapide, il
  la laisse toujours (six fois sur six) ; sous QEMU, selon la charge.
- **La CI, après le push de 6i** : `copies` attendait sur l'hôte la limite
  de /sys de Linux 6.18 (EOVERFLOW à 2^31) ; Linux 7.0, celui de la CI, l'a
  levée (0, la fin du fichier). Le témoin de 6h, dans un brouillon, avait
  disparu : il est passé dans le skill (`temoin-ci.sh`), et il a passé
  sous 7.0 les quatre programmes que 6i ajoutait ou changeait. (Depuis les
  soldes, la CI tourne sous le Linux de référence, et le témoin a cédé la
  place à `.devcontainer/linux-de-reference.sh`.) Un témoin à
  monter soi-même doit avoir ce que les tests ouvrent (`/tmp` : sans lui,
  deux faux échecs).
- **Une sonde en C** : l'ordre d'évaluation des arguments d'un `printf`
  n'est pas défini, et deux appels système passés en arguments s'y font
  dans l'ordre que choisit gcc (de droite à gauche ici) : les séquencer
  dans des instructions à part. Et `alarm` (37) n'existe pas chez nous : une
  limite de temps dans un test passe par `SO_RCVTIMEO`. Un test de signal
  dit « je suis dans l'appel » juste avant l'appel système qui attend,
  après ce qui le prépare (`epoll_create1`, `epoll_ctl`, `clock_gettime`) :
  sinon un signal livré pendant la préparation arrive trop tôt, et le test
  échoue sous la charge seulement. Un délai ajouté dans une copie jetable
  rend ces courses certaines.

## Pièges rencontrés en 6j (9 novembre 2026)

- **Les temporaires des motifs gardent un `Verrou`** : la garde prise dans le
  sujet d'un `match`, d'un `if let` ou d'un `while let`
  (`match X.verrouiller().op() { ... }`) vit jusqu'à la fin du bloc entier,
  interruptions coupées ; ce que le bloc fait ensuite (vider un lot de TLB,
  rendre une pile) attend alors les autres processeurs interruptions
  coupées, et le noyau s'arrête. Écrire `let r = X.verrouiller().op();
  match r { ... }`. Trois endroits trouvés ainsi en 6j (`memoire::servir`, le
  rendeur de piles, deux fois) ; `smp::vider_tlb` nomme désormais l'endroit
  fautif (`#[track_caller]`).
- **Un test ne doit jamais supposer qu'un réveil ou une tâche neuve
  préempte la courante** : l'EEVDF la protège jusqu'à sa première échéance
  (RUN_TO_PARITY), et deux tâches neuves ont des échéances égales que le
  premier de la liste gagne : un test « la neuve s'exécute dès que le verrou
  est rendu » passait trois fois au démarrage et échouait dans
  `tests-qemu`. Construire l'état voulu sans dépendre de ce choix : la
  tâche s'interdit son propre processeur sous le verrou (l'affinité), et
  doit être ailleurs à la ligne suivante.
- **Les tests de temps sous QEMU** : une interruption (un tic : des dizaines
  de microsecondes sous TCG) au mauvais moment fait manquer une fenêtre de
  15 µs un démarrage sur dix. Répéter (vingt parties, au moins une gagnée),
  et mettre les comptes qui varient à la FIN de la ligne attendue (la
  vérification cherche un préfixe). Et `-cpu qemu64` n'a pas de TSC fiable :
  l'heure y est au tic, une borne de 25 µs devient « le prochain tic », et
  deux délais finissent au même tic ; un test de microsecondes doit le voir
  (`tsc::khz().is_none()`) et le dire au lieu d'échouer.
- **Un même journal pour deux ordres légitimes** : le réveil fait sous un
  verrou qui dort prend le processeur dès que le verrou de l'état est rendu
  (depuis c09), et la lettre notée après le réveil passait derrière celle du
  réveillé (GNDdn au lieu de GDNdn). Quand l'ordre du journal n'est pas ce
  que le test prouve, noter la lettre préemption coupée.
- **Mesurer avant d'éclater un verrou, et la mesure se mesure** :
  `make verrous-claude-p` a dit que le tas et le générateur ne se disputent
  pas (moins de cinq attentes par lancement de `claude -p`), que le verrou
  des tables de pages est le plus attendu (1,4 %), et qu'un verrou du
  processus était pris par chaque futex pour lire un pid. Et les deux plus
  longs endroits interruptions coupées étaient l'affichage des statistiques
  lui-même (30 ms sous son verrou) et chaque message du noyau (7 ms pour
  cent octets) : un outil de mesure est le premier à relire. Et à
  remesurer après les corrections : la mesure ne comptait l'attente que du
  premier verrou d'une série (les files des prêtes au tic, le tas sous un
  verrou n'étaient pas comptés) ; comptée pour chaque prise, elle a montré
  que les 256 places de sa table débordaient (76 000 mesures perdues par
  lancement), et qu'un processeur inactif qui tire d'une file d'une seule
  tâche (celle qui s'exécute : rien à tirer) prenait pour rien les deux
  verrous à chaque tic, 7 % des prises de l'ordonnanceur attendues ; une
  file d'au moins deux, et l'attente retombe à 1 %.
- **Tourner sans borne coûte** : les verrous qui dorment pris en tournant sur
  le détenteur, sans borne, ralentissaient les programmes de `tests-qemu`
  de 15 % (27,5 s au lieu de 23,5, pour un budget de 30 s : le premier
  échec de la vérification venait de là, sur `passerelle`), par les
  sections longues (une ligne sur le port série, une copie) ; bornés à
  25 µs, rien ne se perd. Les lecteurs ne tournent pas (Linux 5.11). Et un
  budget de `timeout` doit être mesuré avec sa marge : à 27 s pour 30, un
  tic de plus le fait tomber.
- **La pile du noyau dépend des choix d'inclusion du compilateur** : ajouter
  du code ailleurs a fait sortir `chargeur_elf::charger` de son appelant, et
  la profondeur d'init a pris 800 octets sans qu'une ligne de son chemin
  change. Lire les cadres dans le binaire (`objdump -d` : les
  `sub $N, %rsp` par fonction, comparés entre deux noyaux), nommer la tâche
  la plus profonde dans « Piles du noyau », et chasser les gros objets
  passés par valeur (un `Processus` de 2 Kio copié trois fois) plutôt que
  d'espérer de l'inclusion.
- **Un lot qui ne peut pas se vider sous un verrou doit avoir sa place en
  place** : un `try_reserve` qui échoue sous le verrou des tables aurait fait
  vider le lot (attendre les autres processeurs) interruptions coupées, une
  panique certaine au premier manque de mémoire. Huit cadres dans le lot
  lui-même (la `mmu_gather` de Linux), et une tranche jamais plus grande
  que la place ; 64 en place prenaient 3 Kio de pile de trop.
- **Deux travaux dans l'arbre, un seul à commiter** : la plomberie
  (`commit.sh`) prend tout le dossier ; pour commiter une correction seule
  pendant qu'un autre commit est en cours dans l'arbre, restaurer ses
  fichiers depuis la branche (`git show branche:chemin > chemin`), commiter,
  puis réappliquer l'autre par son script. Garder chaque changement sous
  forme de script rejouable (des remplacements exacts, qui refusent un texte
  absent ou en double, et qui écrivent le fichier à CHAQUE remplacement : un
  script qui relit l'origine à chaque fois et n'écrit qu'à la fin n'applique
  que son dernier remplacement, vu en 6j) rend ce va-et-vient sûr.
- **L'horloge du conteneur** (WSL) avance d'environ une heure sur l'heure
  réelle : dater les notes d'après l'heure de David, pas d'après `date`.
- **Avec quatre processeurs virtuels, deux QEMU à la fois restent la
  limite** du conteneur (8 Go, douze cœurs) ; `make tests-hote` et
  `make tests-qemu` partagent `programmes.cpio` et les dossiers de
  compilation : ne rien construire pendant qu'une vérification tourne.
- **Un test de course doit prouver qu'il mord** : couper le mécanisme qu'il
  vérifie et le voir dire ECHEC. Le test « TLB périmée » de `fautes` disait
  ok sans vidage à distance, deux fois : ses fils dormaient dans une
  barrière de pthread (céder le processeur recharge CR3, ce qui vide le
  TLB), puis, en tournant, le cadre rendu par `munmap` était repris et mis
  à zéro par la première allocation venue, et une relecture périmée lisait
  0 comme une relecture juste. Il a fallu un « puits » (un cadre pris exprès
  après le munmap) et une valeur neuve dans la page reprojetée. Couper le
  mécanisme dans le noyau fait aussi tomber le noyau lui-même (ses piles
  de vmalloc) : ne le couper que pour les programmes, et jouer le test en
  premier dans l'expérience.
- **Une assertion de protocole vaut une relecture** : « aucun je-vais-dormir
  posé quand on prend un verrou qui dort » (le `might_sleep` de Linux),
  ajoutée pour un constat, a trouvé deux cas que trois relecteurs n'avaient
  pas vus (une faute dans `futex`, le client DHCP qui affiche ses essais).
- **Une correction se replie là où sa machinerie existe** : un constat
  attribué au commit qui a défini une notion (la bascule publie la
  courante) se corrige dans celui qui l'exploite entre processeurs (la file
  par processeur) ; au commit visé d'abord, le repli conflictait sur du code
  qui n'existait pas encore. Et un commit « réparé » peut être fondu dans
  son parent par la plomberie (le test des vingt parties dans c10) en
  comparant chaque commit à son parent réel, pas au précédent de la liste.
- **Le shell en arrière-plan** : `a && b && cmd & q=$!` met TOUTE la liste
  en arrière-plan (les variables posées par `a` manquent au premier plan) :
  séparer par `;`. `pgrep -f motif` trouve le shell qui le lance (sa ligne
  de commande contient le motif) : ancrer (`^make tests-qemu`). Jamais de
  `pkill` par nom : le classifieur le refuse, et David aussi.
- **QEMU ne sort pas seul après le démarrage** (le noyau finit en `hlt`) : le
  « demarrage : N s » de `verifier.sh` est le timeout, pas une durée ;
  mesurer le moment de la dernière ligne attendue (`chrono.sh`, 54 s en 6j)
  et mettre DUREE à son double.

## Pièges rencontrés pendant les soldes d'avant 6k (du 9 au 11 novembre 2026)

- **Un outil de repli sans chemin prend toute la copie de travail** :
  `git add -A --` sans chemin ajoute tout ; un repli « message seul » a ainsi
  fait entrer les docs en cours dans un commit du noyau, et tous ses suivants.
  Un outil qui prend des chemins n'ajoute RIEN quand il n'en a pas ; et
  vérifier ce que touche chaque commit (`git log --stat BASE..`) avant de
  signer.
- **Replier une correction dans un commit déjà vérifié** change l'arbre de ce
  commit et de tous ses suivants : leur vérification est à refaire. Replier
  toutes les corrections d'une relecture d'abord, puis vérifier la chaîne une
  fois.
- **Signer demande une fenêtre VS Code ouverte sur le conteneur** : c'est elle
  qui fait suivre l'agent SSH de 1Password (`/tmp/vscode-ssh-auth-*.sock`) ;
  après un redémarrage du PC, aucune prise ne répond tant qu'elle n'est pas
  ouverte (`ssh-add -l` : code 2).
- **Une chaîne en partie poussée** : la suite se repose sur la partie signée
  (mêmes arbres, autres parents) avant le moindre repli, sinon les outils qui
  rejouent depuis l'ancienne base refont les commits poussés, sans signature.
- **Le journal d'un démarrage en échec** se garde (la voie est effacée au
  commit suivant) : sans lui, un échec isolé ne se comprend plus.
- **Un relecteur trouve ce que la vérification ne voit pas** : les deux
  relectures des soldes ont trouvé un réveil perdu (une course entre `connect`
  et `poll`), une copie qui paniquait encore, un signal sans personne pour le
  prendre ; aucun test ne les montrait.
- **Un test instable corrigé dans l'étape courante a des copies dans les
  étapes passées**, que la CI repasse : `linux/attente` et TCP_QUICKACK,
  corrigés dans 6k seulement, ont rougi la CI du push suivant dans 6i et 6j ;
  `reprise`, corrigé en 6i, est tombé en 6h. Chercher le test dans chaque
  étape (`grep -l` sur un message du test) et corriger toutes ses copies dans
  le même commit (l'exception de CLAUDE.md) ; puis vérifier ces étapes deux à
  la fois : la charge montre les autres.
- **`actions/cache` ne garde rien d'une action rouge** : un téléchargement
  fait pendant une CI qui échoue est refait à la suivante, et une panne du
  site (Launchpad, 503) la fait échouer encore. Ce qui se télécharge se garde
  en trois temps (`actions/cache/restore`, le téléchargement dans sa propre
  étape, `actions/cache/save`).
- **Une marge en pourcentage autour d'une valeur arrondie** dépend de la
  taille de cette valeur : `tcp` comparait le débit calculé à 15 % près d'un
  SRTT que TCP_INFO tronque à la µs, assez à 10 µs, pas à 5 (la CI sous
  KVM). Calculer l'intervalle exact que l'arrondi permet.
