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
- Pas de `rm -rf "$VARIABLE"` dans les commandes : la protection de Claude Code
  les bloque ; utiliser `git worktree remove` et des chemins écrits en entier.
