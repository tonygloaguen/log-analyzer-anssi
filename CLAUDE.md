# Instructions projet - log-analyzer-anssi

## Périmètre par défaut
Quand tu analyses ce projet :
- Commence par README.md, docker-compose.yml, Dockerfile, requirements.txt, pytest.ini.
- N’explore src/ et tests/ que si nécessaire ou si demandé.

## Priorités
1. sécurité
2. robustesse Docker
3. dette technique
4. qualité tests

## Format de réponse préféré
- Vue d’ensemble
- Risques critiques
- Actions prioritaires
- Correctifs concrets

## Style attendu
- Français
- Structuré
- Peu verbeux
- Pas de blabla

---

## Stratégie de debug

Avant tout patch, tracer l'exécution logique ligne par ligne :
1. Identifier la fonction en cause (lire le code, pas les logs seuls).
2. Injecter un `python3 -c` minimal reproduisant le bug en isolation.
3. Vérifier les pièges connus :
   - **ElementTree** : `bool(element)` est `False` si l'élément n'a pas d'enfants. Utiliser `is not None` à la place de `or`.
   - **HMAC_SECRET** : variable d'environnement obligatoire — absence → `RuntimeError`.
   - **async dans contexte sync** : `asyncio.get_event_loop().run_until_complete()` uniquement si la boucle n'est pas déjà en cours.
4. Corriger la cause racine, pas le symptôme.
5. Vérifier la non-régression : `pytest tests/ -v`.

## Modules sensibles

| Module | Risque | Précaution |
|---|---|---|
| `core/log_integrity.py` | HMAC — clé secrète | Ne jamais logger `secret`. Utiliser `compare_digest`. |
| `detectors/byovd_detector.py` | Parsing XML externe | Utiliser `defusedxml` si disponible ; sinon interdire DTD. |
| `collectors/network_collector.py` | Subprocess tcpdump | Valider `iface` par regex `[a-zA-Z0-9_:-]{1,20}` avant passage shell. |
| `nodes/ransomware_behavior_analyst.py` | Appel LLM externe | Timeout 30s strict. Aucune donnée brute dans le prompt (résumé uniquement). |
| `notifiers/alert_dispatcher.py` | Credentials SMTP/ntfy | Lire depuis env uniquement, jamais depuis args CLI. |
| `scripts/update_loldrivers.sh` | Écriture fichier système | Valider JSON avant mv. Backup `.bak` systématique. |

## Cible de déploiement

- **Host** : `gloaguen@192.168.1.31` (Raspberry Pi 4, ARM64)
- **Répertoire** : `/opt/log-analyzer-anssi`
- **Modèle LLM** : `granite3.3:8b` (Q4_K_M, ~5 Go)
- **Swap requis** : 4 Go (`CONF_SWAPSIZE=4096` dans `/etc/dphys-swapfile`)
