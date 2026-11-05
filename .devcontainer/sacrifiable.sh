# Lu par Claude Code avant chaque commande de son outil Bash, dans le shell qui
# la lance (CLAUDE_ENV_FILE, devcontainer.json).
#
# Quand le conteneur atteint son plafond de mémoire, le noyau tue le processus
# qui a le plus gros score : sa mémoire, plus oom_score_adj en millièmes du
# plafond. +500, sur 8 Go, compte pour 4 Go : QEMU, cargo et les mutants, qui
# héritent de ce réglage, passent avant les sessions et le serveur, à +0. Une
# session perdrait son travail ; une commande tuée se relance et son échec se
# voit dans la session.
#
# Pourquoi pas protéger le serveur (une valeur négative) : il faut pour cela
# CAP_SYS_RESOURCE, et ses enfants en hériteraient jusqu'à QEMU, ce qu'on veut
# justement éviter. Monter un processus ne demande aucun droit.
echo 500 2>/dev/null >"/proc/$$/oom_score_adj"
