# 7. Résultats, bilan et conclusion

## 7.1 Comparaison avant / après

| Contrôle | Avant (As-Is) | Après (final) |
|---|---|---|
| Pytest | 3 tests fonctionnels | 6 tests, dont 3 tests de sécurité — tous réussis |
| Gitleaks | Token GitHub détecté | Aucun secret |
| Bandit | 7 alertes (3 HIGH, 2 MEDIUM, 2 LOW) | 0 alerte (B104 exemptée, EXC-001) |
| Semgrep | [à compléter] | Remplacé par SonarQube |
| SonarQube | Gate en échec : note E, 6 vulnérabilités, couverture 0 % | Gate réussi : note A, couverture 89,2 % (S8392 faux positif EXC-001, S4502 risque accepté EXC-002) |
| Trivy fs (SCA) | 3 CVE HIGH (Flask, Werkzeug) | 0 CVE HIGH/CRITICAL |
| Checkov (IaC) | 3 échecs (conteneur root, pas de HEALTHCHECK, workflow sans `permissions`) | 0 échec (48 contrôles Dockerfile, 320 contrôles workflows) |
| SBOM (Trivy) | Non généré | SBOM CycloneDX publié en artefact |
| Trivy image | [à compléter] (`python:3.8`, root) | 0 CVE bloquante (166 constats non bloquants : sans correctif ou sous les seuils) |
| OWASP ZAP | En-têtes CSP, X-Frame-Options, X-Content-Type-Options absents | Règles 10020, 10021, 10038 respectées, en staging |
| Security Gate (politique) | — | **PASS** sur la version finale, **BLOCK** sur la version vulnérable (test négatif) |
| Déploiement | Aucun | Staging puis production après approbation, durcis, avec retour arrière automatique |
| **Statut du pipeline** | **Vert, mais sans aucune garantie (mode audit)** | **Vert, avec Security Gate bloquant** |

Les deux pipelines verts n'ont pas du tout la même valeur : le premier ne bloquait
rien, le second prouve que chaque contrôle a été passé.

![Capture 6 — Pipeline final entièrement vert](images/06-pipeline-final-vert.png)

> **Capture 6** — Pipeline final : tous les jobs passent avec les Quality Gates activés.

## 7.2 Couverture OWASP Top 10 (2021)

| Catégorie OWASP | Vulnérabilité du projet | Outil(s) qui la détecte(nt) |
|---|---|---|
| A01 — Contrôle d'accès défaillant | Protection CSRF absente | SonarQube (S4502) — risque accepté EXC-002 |
| A02 — Défaillances cryptographiques | MD5 pour les mots de passe | Bandit (B324), SonarQube (S4790) |
| A03 — Injection | SQLi, injection de commandes, XSS, SSTI | Bandit (B608, B605), tests Pytest (SonarQube Community ne les détecte pas) |
| A05 — Mauvaise configuration de sécurité | Mode debug, en-têtes absents, conteneur root | Bandit (B201), ZAP, Checkov (CKV_DOCKER_3) |
| A06 — Composants vulnérables et obsolètes | Flask 2.0.1, Werkzeug 2.0.1, `python:3.8` | Trivy fs, Trivy image (+ SBOM) |
| A07 — Défaillances d'identification | Clé de session en dur | Gitleaks, Bandit (B105) |

## 7.3 Difficultés rencontrées et enseignements

1. **Un gate peut être vert sans rien analyser.** Bandit pointait vers un mauvais
   chemin (`app.py` au lieu de `app/`) et réussissait sans rien scanner. Il faut
   toujours vérifier qu'un gate échoue sur un code vulnérable connu.
2. **Corriger le code ne suffit pas.** Après la correction de `app.py`, le pipeline est
   resté rouge à cause des dépendances. Chaque couche (code, dépendances, image) doit
   être traitée.
3. **Les vulnérabilités viennent aussi des outils.** Trivy image a signalé des CVE dans
   les bibliothèques embarquées par pip, et non dans nos dépendances. Supprimer ce qui
   n'est pas nécessaire à l'exécution est souvent la meilleure correction.
4. **Un scanner de secrets ne détecte pas tout.** La clé AWS d'exemple est ignorée par
   Gitleaks. La défense en profondeur (plusieurs outils et revue de code) reste nécessaire.
5. **Un secret poussé sur Git est compromis.** Le retirer du code ne le retire pas de
   l'historique : il faut le révoquer. Le hook pre-commit Gitleaks bloque ce cas avant
   le push.

## 7.4 Pistes d'amélioration

- **Épingler les images des outils** (`aquasec/trivy:<version>`, `zaproxy:<version>`…)
  au lieu de `latest`, voire par digest `@sha256:`, pour des builds reproductibles et
  pour limiter le risque d'attaque sur la chaîne d'approvisionnement.
- **Publier les résultats au format SARIF** dans l'onglet *Security* de GitHub
  (Code scanning) pour suivre les alertes dans le temps.
- **Signer l'image** (Cosign) et attacher le SBOM comme attestation.
- **Mettre à jour automatiquement les dépendances** avec Dependabot ou Renovate.
- **Scanner l'historique Git complet** avec Gitleaks (`detect`) en plus du répertoire courant.
- **DAST authentifié** : configurer ZAP pour se connecter et tester `/notes`.

## 7.5 Conclusion

Le projet a montré l'ensemble du cycle DevSecOps sur une application réelle :
mesurer (As-Is), imposer une politique (Quality Gates), corriger (remédiation) et
gérer les exceptions de façon traçable (exemptions). Le pipeline final combine neuf
contrôles automatisés couvrant le code, les secrets, les dépendances, l'image Docker
et l'application en cours d'exécution. Désormais, aucun code présentant une
vulnérabilité HIGH ou CRITICAL corrigeable ne peut être livré sans une décision
explicite et documentée.
