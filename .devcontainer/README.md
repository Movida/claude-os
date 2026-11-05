# Le conteneur et Remote Control

Le conteneur a pour processus principal un superviseur (`remote-control.sh`, copié dans l'image) : il lance `claude remote-control`, le relance s'il s'arrête, et l'arrête proprement avec le conteneur. Aucune commande à taper, aucune fenêtre VS Code à garder ouverte. Le pourquoi de chaque choix est en tête du script.

## Au quotidien

- **Voir ce qui se passe :** `tail -f ~/.claude/remote-control.log`. Le journal ne garde que ce qui change : quelques dizaines de lignes par jour. Il note aussi les gels (veille de Windows, mémoire saturée) et les processus tués par le plafond de mémoire.
- **Relancer le serveur :** `kill <pid>`, avec le pid donné par `pgrep -f '^claude remote-control'`. Le superviseur le relance, et le serveur réveille les sessions de fils qu'il avait notées en s'arrêtant.
- **L'arrêter un moment** (pour le lancer à la main dans un terminal, par exemple) : `touch ~/.claude/remote-control.pause`. Il repart après `rm ~/.claude/remote-control.pause`.
- **Arrêter le conteneur :** il survit à la fermeture de VS Code, c'est voulu. Depuis WSL : `docker stop <conteneur>`, avec le nom donné par `docker ps`.
- **Modifier le superviseur :** il est dans l'image, donc il faut reconstruire le conteneur (« Rebuild Container »). Tester d'abord avec `.devcontainer/test-remote-control.sh`, qui utilise un faux serveur et peut tourner à côté du vrai.

## La bascule, une seule fois

Le `Dockerfile` et `devcontainer.json` changent : `docker restart` ne suffit pas, il faut reconstruire. Une reconstruction efface tout ce qui n'est ni dans le dépôt ni dans le volume `~/.claude` : `/tmp` (les brouillons des sessions), `~/.rustup` et `~/.cache/claude-os`, que `cargo` et `make` retéléchargent. Elle coupe aussi toutes les sessions : à faire quand aucune n'a de travail en cours.

1. Dans `~/claude-os` sous WSL, avoir ces commits sur la branche en cours.
2. Dans VS Code : « Dev Containers: Rebuild Container ».
3. Dans un terminal du conteneur, vérifier le processus principal : `tr '\0' ' ' </proc/1/cmdline` commence par `/sbin/docker-init`, et `pgrep -a -f remote-control.sh` montre le superviseur.
4. Vérifier l'arrêt propre, depuis WSL : `docker restart <conteneur>`. Le journal doit alors contenir `Environment preserved` s'il y avait une session, puis `superviseur arrete` et `superviseur lance`.

Le gros journal d'avant part dans `~/.claude/remote-control.log.1` au premier démarrage : `rm` possible une fois la bascule vérifiée.

Si le conteneur ne démarre plus, `docker logs <conteneur>` depuis WSL montre le superviseur. Pour revenir en arrière : remettre l'ancien `.devcontainer/` dans `~/claude-os`, puis reconstruire.

## Côté Windows, à faire soi-même

Ce sont les seules causes de coupure que le conteneur ne peut pas traiter seul. Le serveur est prévu pour reprendre après une veille (il repère le trou et se reconnecte), mais rien ne répond tant qu'elle dure.

**Pas de veille sur secteur**, dans PowerShell :

```powershell
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
# Portable uniquement : rabattre l'écran ne fait rien sur secteur.
powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
powercfg /setactive SCHEME_CURRENT
```

La batterie garde ses réglages. Pour revenir à 30 minutes : `powercfg /change standby-timeout-ac 30`. Vérifier ce qui a réveillé ou endormi le PC : `powercfg /lastwake` et `powercfg /requests`.

**Tout redémarrer à l'ouverture de session**, après un redémarrage de Windows :

1. Docker Desktop, Settings, General : cocher « Start Docker Desktop when you sign in to your computer ».
2. Créer la tâche, dans un PowerShell en administrateur (ajouter `-d <distribution>` au début de `-Argument` si le dépôt n'est pas dans la distribution WSL par défaut) :

```powershell
$action  = New-ScheduledTaskAction -Execute 'wsl.exe' -Argument '-e bash -lc ~/claude-os/.devcontainer/demarrer-conteneur.sh'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
Register-ScheduledTask -TaskName 'claude-os conteneur' -Action $action -Trigger $trigger
```

Pour l'essayer sans redémarrer : conteneur arrêté, `Start-ScheduledTask -TaskName 'claude-os conteneur'`, puis `docker ps` dans WSL. Pour la retirer : `Unregister-ScheduledTask -TaskName 'claude-os conteneur'`.

Cette partie n'a pas pu être essayée depuis le conteneur, qui n'a ni Windows ni Docker. Si le script dit `aucun conteneur`, comparer `$HOME/claude-os` avec le label `devcontainer.local_folder` donné par `docker inspect <conteneur>`.

## La mémoire

Le conteneur est plafonné à 8 Go (`devcontainer.json`), la machine WSL en a 12 : ce plafond protège WSL, rien à changer de ce côté. Quand il est atteint, le noyau tue un processus, et `sacrifiable.sh` fait que ce soit une commande (QEMU, cargo, un mutant) et non une session ou le serveur. Cela ne remplace pas la règle du projet (au plus deux QEMU à la fois, sous `timeout`) : avant de tuer, le noyau vide le cache des fichiers, et tout ralentit.
