# Sécurité

claude-os est un projet d'apprentissage : il n'est pas fait pour tourner en production, ni pour protéger des données. Ses protections (W^X, SMEP, SMAP, isolation Wasm…) sont là pour apprendre comment elles marchent, pas pour être éprouvées.

## Signaler un problème

Pour une faille dans le code du dépôt, ouvrez de préférence un signalement privé : onglet **Security**, puis **Report a vulnerability**. Une issue publique convient aussi pour un défaut sans conséquence au-delà du projet.

Si vous trouvez un secret publié par erreur (un jeton, une clé) dans le dépôt ou son historique, signalez-le en privé par la même voie, sans le recopier.

## Hors du périmètre

Le binaire de Claude Code que télécharge l'étape 6d appartient à Anthropic et n'est pas distribué ici. Une faille de Claude Code lui-même se signale à Anthropic : https://www.anthropic.com/responsible-disclosure-policy
