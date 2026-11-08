# Le conteneur et Remote Control

Le conteneur a pour processus principal un superviseur (`remote-control.sh`, copié dans l'image) : il lance `claude remote-control`, le relance s'il s'arrête, et l'arrête proprement avec le conteneur. Aucune commande à taper, aucune fenêtre VS Code à garder ouverte. Le pourquoi de chaque choix est en tête du script.

## Au quotidien

- **Voir ce qui se passe :** `tail -f ~/.claude/remote-control.log`. Le journal ne garde que ce qui change : quelques dizaines de lignes par jour. Il note aussi les gels (veille de Windows, mémoire saturée) et les processus tués par le plafond de mémoire.
- **Voir ce qui se passe côté WSL :** `tail ~/.local/state/claude-os/conteneur.log`, ce qu'ont fait le raccourci d'extinction et la relance au démarrage de WSL, une ligne par étape, avec la réponse de Docker quand il a fallu l'attendre.
- **Relancer le serveur :** `kill <pid>`, avec le pid donné par `pgrep -f '^claude remote-control'`. Le superviseur le relance, et le serveur réveille les sessions de fils qu'il avait notées en s'arrêtant.
- **L'arrêter un moment** (pour le lancer à la main dans un terminal, par exemple) : `touch ~/.claude/remote-control.pause`. Il repart après `rm ~/.claude/remote-control.pause`.
- **Arrêter le conteneur :** il survit à la fermeture de VS Code, c'est voulu, à condition que Docker Desktop n'ait pas été lancé par VS Code (plus bas, « Tout redémarrer à l'ouverture de session »). Depuis WSL : `~/claude-os/.devcontainer/arreter-conteneur.sh` (`docker stop`, puis `sync`) ; pour éteindre le PC, le raccourci « Eteindre claude-os » (plus bas).
- **Après un redémarrage du conteneur :** recharger les fenêtres VS Code restées ouvertes (« Developer: Reload Window »). Sinon, chacune essaie de se reconnecter toutes les 30 s pendant 3 heures, sans y arriver, et lance à chaque essai un serveur de connexion. Le superviseur arrête ceux qui sont en trop et le note au journal (`serveurs de connexion en trop`), mais la fenêtre reste morte tant qu'on ne la recharge pas.
- **Modifier le superviseur :** il est dans l'image, donc il faut reconstruire le conteneur (voir plus bas). Tester d'abord avec `.devcontainer/test-remote-control.sh`, qui utilise un faux serveur et peut tourner à côté du vrai.
- **Après un arrêt brutal** (Windows éteint ou redémarré sans arrêter le conteneur, coupure de courant) : le serveur n'a pas pu noter ses sessions, et `bridge-pointer.json`, qui garde son environnement, est resté à sa dernière heure. Le serveur jette ce fichier quand il a plus de 4 heures, et en inscrivait alors un nouveau : les fils perdaient leur machine pour de bon. Le superviseur remet sa date à l'heure avant chaque lancement, et le journal le dit (`pointeur vieux de N h, remis a l'heure`) ; l'adresse que donne ensuite le serveur (`environment=env_…`) doit garder le même identifiant. S'il écrit `Could not reuse the previous environment`, le service a refusé l'ancien : les fils de la veille sont à relancer. Docker, lui, prend cet arrêt pour un échec (`--restart=on-failure`) et relance le conteneur à son propre démarrage, souvent avant que les dossiers de WSL soient montés : `docker inspect` montre alors le code 127 et `failed to fulfil mount request`. Sans conséquence, le service de WSL le démarre ensuite (plus bas).
- **Au démarrage, `CCR v2 worker registration failed` avec un 404 :** sans effet. C'est la session que `bridge-pointer.json` garde pour l'environnement, terminée depuis ; le serveur continue et réveille les autres. Ne pas effacer ce fichier, qui garde aussi l'environnement : sans lui, le serveur en inscrit un nouveau et oublie les sessions.

## Reconstruire le conteneur

Après un changement du `Dockerfile`, de `devcontainer.json` ou du superviseur, `docker restart` ne suffit pas. Une reconstruction efface tout ce qui n'est ni dans le dépôt ni dans le volume `~/.claude` : `/tmp` (les brouillons des sessions), `~/.rustup` et `~/.cache/claude-os`, que `cargo` et `make` retéléchargent. Elle coupe aussi toutes les sessions : à faire quand aucune n'a de travail en cours. Elles reviennent ensuite toutes seules, même si le nom de la machine change.

La reconstruction commence par `docker rm -f` (CLI devcontainer 0.90.0), avant de construire l'image. Le serveur meurt donc par SIGKILL, sans noter ses sessions, et une image qui ne se construit pas laisse sans conteneur. D'où les deux premières étapes :

1. Essayer l'image depuis WSL, ce qui ne coupe rien : `docker build -t claude-os-essai ~/claude-os/.devcontainer`, puis `docker run --rm claude-os-essai qemu-system-x86_64 --version`. Le cache de Docker resservira à la reconstruction, qui ne recompile pas QEMU.
2. Arrêter le serveur proprement, dans un terminal du conteneur : `touch ~/.claude/remote-control.pause`. Le journal doit dire `Environment preserved`, puis `serveur arrete pour la pause`. Pas `kill` : le superviseur le relancerait aussitôt.
3. Dans VS Code : « Dev Containers: Rebuild Container ».
4. Dans un terminal du nouveau conteneur : `rm ~/.claude/remote-control.pause`. Le fichier est dans le volume : tant qu'il reste, le serveur ne repart pas (le journal le rappelle).
5. Vérifier le processus principal : `tr '\0' ' ' </proc/1/cmdline` commence par `/sbin/docker-init`, et `pgrep -a -f remote-control.sh` montre le superviseur.
6. Vérifier l'arrêt propre, depuis WSL : `docker restart <conteneur>`. Le journal doit alors contenir `Environment preserved` s'il y avait une session, puis `superviseur arrete` et `superviseur lance`. Recharger ensuite la fenêtre VS Code.

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

**Éteindre le PC par le raccourci « Eteindre claude-os »**, pas par le menu Démarrer. Éteindre Windows arrête la machine WSL sans attendre le conteneur : le 6 novembre, le serveur n'a pas pu noter ses sessions, et rien n'est resté au journal. Le raccourci lance `arreter-conteneur.sh --eteindre` : `docker stop` (45 s au plus), `sync`, puis l'extinction. En cas d'échec, il l'affiche et attend Entrée avant d'éteindre quand même. Pour le créer sur le bureau, dans PowerShell (ajouter `-d <distribution>` au début de `Arguments` si le dépôt n'est pas dans la distribution WSL par défaut) :

```powershell
$raccourci = (New-Object -ComObject WScript.Shell).CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\Eteindre claude-os.lnk")
$raccourci.TargetPath = "$env:WINDIR\System32\wsl.exe"
$raccourci.Arguments = '-e bash -lc "~/claude-os/.devcontainer/arreter-conteneur.sh --eteindre"'
$raccourci.IconLocation = "$env:WINDIR\System32\shell32.dll,27"
$raccourci.Save()
```

Un clic droit sur le raccourci l'épingle au menu Démarrer. `--redemarrer` au lieu de `--eteindre` redémarre le PC. Pour l'essayer sans rien éteindre, dans WSL : `~/claude-os/.devcontainer/arreter-conteneur.sh`, qui doit dire `conteneur … arrete proprement`, puis `~/claude-os/.devcontainer/demarrer-conteneur.sh` pour le relancer. Une mise à jour qui redémarre le PC d'elle-même ne passe pas par le raccourci : le serveur garde alors son environnement, mais une session en cours ne repart qu'au prochain message de son fil.

**Tout redémarrer à l'ouverture de session**, après un redémarrage de Windows. Indispensable avec le raccourci : après un arrêt propre, Docker ne relance pas le conteneur (`--restart=on-failure` ne relance que les échecs). C'est un service de WSL qui le fait, à chaque démarrage de WSL : Docker Desktop démarre la distribution en s'ouvrant, pour y lancer son relais.

1. Faire lancer Docker Desktop par Windows dès l'ouverture de session, avant que VS Code s'en charge. Dans un PowerShell en administrateur, une tâche planifiée (la première ligne retire celle des versions d'avant, qui lançait `demarrer-conteneur.sh` dans une fenêtre console et s'est terminée le 8 novembre en `0xC000013A` avant que Docker réponde) :

```powershell
Unregister-ScheduledTask -TaskName 'claude-os conteneur' -Confirm:$false -ErrorAction SilentlyContinue
$action   = New-ScheduledTaskAction -Execute "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$reglages = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'Docker Desktop' -Action $action -Trigger $trigger -Settings $reglages
```

Puis, dans Docker Desktop, Settings, General : décocher « Start Docker Desktop when you sign in to your computer », que la tâche remplace.

Pourquoi : quand l'extension Dev Containers ne trouve pas Docker, elle lance Docker Desktop elle-même, comme un processus enfant de l'hôte d'extensions de VS Code. Windows le tue avec cet hôte, sans qu'il écrive une ligne, dès qu'une fenêtre se recharge, se rouvre dans le conteneur ou se ferme, et le conteneur s'arrête avec lui. Le 8 novembre, VS Code, rouvert seul à l'ouverture de session, a lancé Docker 7 s après son départ ; l'option de Docker est arrivée 52 s plus tard, trouvant Docker déjà lancé, et Docker est tombé trois fois dans la journée, à chaque arrêt de l'hôte d'extensions (journal de VS Code, `main.log`). Une tâche d'ouverture de session part avant : celle des versions d'avant avait démarré 28 s avant VS Code. Ses réglages : ni limite de durée (3 jours par défaut, au bout desquels la tâche arrêterait Docker), ni arrêt quand le PC passe sur batterie.

Qui a lancé Docker Desktop, dans PowerShell : tout sauf `Code` va bien (`svchost` pour la tâche, `explorer` pour le menu Démarrer). Avec `Code`, il tombera avec VS Code : le quitter (icône de la barre des tâches, « Quit Docker Desktop »), le relancer depuis le menu Démarrer, puis, dans WSL, `systemctl --user start claude-os-conteneur`.

```powershell
Get-CimInstance Win32_Process -Filter "Name='Docker Desktop.exe'" | Sort-Object CreationDate | Select-Object -First 1 | ForEach-Object { (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue).ProcessName }
```

2. Dans WSL, une fois, installer le service `claude-os-conteneur` (le fichier reste dans le dépôt, systemd y fait un lien) :

```bash
loginctl show-user "$USER" -p Linger   # doit dire Linger=yes ; sinon : sudo loginctl enable-linger "$USER"
systemctl --user enable ~/claude-os/.devcontainer/claude-os-conteneur.service
```

Sans « linger », systemd ne démarre les services de l'utilisateur qu'à sa première connexion, et rien ne relancerait le conteneur. Le service attend que Docker réponde (15 minutes au plus), démarre le conteneur en réessayant pendant une minute si les montages de WSL ne sont pas prêts, et le redémarre s'il le trouve lancé par Docker sans le dépôt (voir `demarrer-conteneur.sh`). Pour l'essayer sans redémarrer : `~/claude-os/.devcontainer/arreter-conteneur.sh`, puis `systemctl --user start claude-os-conteneur` ; `tail ~/.local/state/claude-os/conteneur.log` doit dire `conteneur … demarre`. Après une modification du fichier : `systemctl --user daemon-reload`. Pour le retirer : `systemctl --user disable claude-os-conteneur`.

Les deux scripts trouvent le conteneur par ses labels `devcontainer.local_folder` (le chemin vu de Windows, `\\wsl.localhost\Ubuntu\...`) et `devcontainer.config_file` (le chemin de WSL), voir `conteneur-du-depot.sh`. S'ils disent `aucun conteneur` ou `ne tourne pas` à tort, comparer `$HOME/claude-os` avec ces labels : `docker inspect <conteneur> --format '{{json .Config.Labels}}'`.

## La mémoire

Le conteneur est plafonné à 8 Go (`devcontainer.json`), la machine WSL en a 12 : ce plafond protège WSL, rien à changer de ce côté. Quand il est atteint, le noyau tue un processus, et `sacrifiable.sh` fait que ce soit une commande (QEMU, cargo, un mutant) et non une session ou le serveur. Cela ne remplace pas la règle du projet (au plus deux QEMU à la fois, sous `timeout`) : avant de tuer, le noyau vide le cache des fichiers, et tout ralentit.
