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
     FS et GS. Essayer chaque fois depuis un programme : `int n`, `icebp`,
     TF avant `syscall`, `mov ss` puis `syscall`, NMI injecté par le
     moniteur QEMU (`nmi`) pendant qu'il tourne.
   - **Le temps** : une boucle d'appels système coûteux doit, elle aussi,
     épuiser le budget de temps d'un programme. Pas de gros travail
     interruptions coupées (les tics de l'horloge se perdent).
   - **Pour une bibliothèque testée sur l'hôte** (étape 4) : faire échouer
     un test exprès pour vérifier que `make tests-hote` le signale ; faire « muter »
     le code (un décalage de un) pour vérifier qu'un contrôle le détecte ;
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
   l'étape a fait, ce qui reste à faire), dans un commit
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
