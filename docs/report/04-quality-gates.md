# 4. Phase « To-Be » : Quality Gates

## 4.1 Principe

Un **Quality Gate** est un seuil de sécurité qui fait échouer le pipeline lorsqu'il
est dépassé. Une fois la baseline connue, le mode audit est supprimé
(commit `d57bef6`) :

- suppression de tous les `continue-on-error: true` ;
- suppression de tous les `|| true` sur les commandes de scan ;
- ajout de `--exit-code 1` à Trivy et de `--error` à Semgrep (remplacé ensuite par
  SonarQube) pour que les outils renvoient un code d'erreur quand ils trouvent une
  vulnérabilité ;
- le build Docker dépend désormais des analyses statiques (`needs:`).

## 4.2 Politique appliquée

| Outil | Commande (extrait) | Le pipeline échoue si… |
|---|---|---|
| Pytest | `python -m pytest tests/` | un test échoue |
| Gitleaks | `gitleaks dir /repo` | un secret est détecté |
| Bandit | `bandit -r app -ll -c bandit.yaml` | une alerte MEDIUM ou plus n'est pas exemptée |
| SonarQube | `sonar-scanner` avec `sonar.qualitygate.wait=true` | le Quality Gate « DevSecOps » échoue (voir 4.6) |
| Trivy fs | `trivy fs --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1` | une dépendance a une CVE HIGH/CRITICAL **corrigeable** |
| Checkov | `checkov --config-file .checkov.yaml` | un contrôle IaC échoue sur le Dockerfile ou un workflow (remplace Hadolint) |
| Trivy image | `trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1` | l'image a une CVE HIGH/CRITICAL **corrigeable** |
| OWASP ZAP | `zap-baseline.py -c rules.tsv -I` | une des règles 10020, 10021, 10038 est déclenchée |

### Justification des seuils

- **`--ignore-unfixed` (Trivy)** : une CVE sans correctif disponible ne peut pas être
  corrigée par l'équipe ; bloquer le pipeline n'apporterait rien. Ces CVE restent
  visibles dans le rapport et sont suivies.
- **Bandit à partir de MEDIUM** : l'injection SQL (B608) est classée MEDIUM par
  Bandit. Un seuil HIGH l'aurait laissée passer.
- **ZAP avec `rules.tsv` et `-I`** : le mode baseline produit beaucoup d'avertissements
  informatifs. Le fichier `rules.tsv` choisit précisément les règles bloquantes
  (`FAIL`), et `-I` empêche les simples avertissements de faire échouer le job.

## 4.3 Résultat : le pipeline passe au rouge

Dès l'activation des Quality Gates, le pipeline échoue : les vulnérabilités
identifiées pendant la phase As-Is bloquent désormais la livraison. Le job de
build et de DAST n'est même pas lancé, puisqu'il dépend des analyses statiques.

![Capture 5 — Pipeline en échec après activation des Quality Gates](images/05-quality-gate-rouge.png)

> **Capture 5** — Pipeline rouge : les Quality Gates bloquent la livraison du code vulnérable.

C'est le comportement attendu : **un code vulnérable ne peut plus être livré**.
La seule façon de repasser au vert est de corriger les vulnérabilités (chapitre 5)
ou de documenter une exemption justifiée (chapitre 6).

## 4.4 Correction en plusieurs étapes

| Commit | Contenu | Statut du pipeline | Gate en échec |
|---|---|---|---|
| `d57bef6` | Activation des Quality Gates | Rouge | SAST (Semgrep) ; le build et le DAST ne sont pas lancés |
| `2e8c056` | Correction du code et du Dockerfile, ajout de Trivy fs | Rouge | SCA (Trivy fs) : dépendances toujours obsolètes |
| `6cf55c3` | Mise à jour des dépendances, SonarQube, Hadolint, Syft, exemptions | Vert en local (branche) | — |
| Architecture multi-niveaux | Pipeline en 6 niveaux, Security Gate centralisé, Checkov, SBOM Trivy, staging/production | Vert en local | — |

**Évolution vers un Security Gate centralisé.** Dans la version finale (chapitre 2),
les scanners ne bloquent plus eux-mêmes : ils produisent leurs rapports au niveau 2, et le
niveau 4 applique une politique unique ([`security-policy.json`](../../security-policy.json))
qui décide BLOCK ou PASS. Les seuils du tableau 4.2 sont conservés ; s'y ajoute un seuil
**CVSS ≥ 7,0** pour Trivy. Testée sur la version vulnérable, la politique bloque bien :
4 alertes Bandit, 8 CVE Trivy et 3 contrôles Checkov.

La correction partielle du commit `2e8c056` montre l'intérêt d'avoir plusieurs
gates indépendants : le code était corrigé, mais Trivy a continué de bloquer tant que
Flask et Werkzeug n'étaient pas mis à jour.

## 4.5 Leçon : un gate mal configuré est un faux sentiment de sécurité

Dans le commit `d57bef6`, l'étape Bandit était **verte** alors que le code contenait
une injection SQL. La cause : la commande visait `bandit -r app.py`, un fichier qui
n'existe pas à la racine du dépôt (le code est dans `app/app.py`). Bandit n'analysait
donc rien et renvoyait un succès.

La commande a été corrigée en `bandit -r app -ll -c bandit.yaml`. Bonnes pratiques
qui en découlent :

- vérifier qu'un gate **échoue réellement** sur un code vulnérable connu avant de lui
  faire confiance (test négatif) ;
- afficher un résumé des alertes dans les logs (étape *Bandit findings summary*) pour
  repérer un rapport anormalement vide.

## 4.6 Quality Gate SonarQube « DevSecOps »

Le Quality Gate par défaut de SonarQube (*Sonar way*) ne porte que sur le **nouveau
code** : lors de la première analyse, il ne bloque rien. Un Quality Gate personnalisé,
nommé **DevSecOps**, a donc été créé et associé au projet. Ses conditions portent sur
l'**ensemble du code** :

| Métrique | Condition d'échec | Signification |
|---|---|---|
| Note de sécurité (`security_rating`) | pire que C | au moins une vulnérabilité HIGH ou BLOCKER |
| Note de fiabilité (`reliability_rating`) | pire que C | au moins un bug HIGH ou BLOCKER |
| Couverture de tests (`coverage`) | inférieure à 70 % | code insuffisamment testé |
| Nouvelles alertes (`new_violations`) | supérieur à 0 | ajoutée automatiquement par SonarQube |

Les notes SonarQube vont de A à E : A = aucune vulnérabilité, B = au moins une LOW,
C = au moins une MEDIUM, D = au moins une HIGH, E = au moins une BLOCKER. Le seuil
« pire que C » applique donc la même politique HIGH/CRITICAL que Trivy.

La couverture est calculée par Pytest (`pytest-cov`) dans le job `unit-tests`, puis
transmise au job SonarQube sous forme d'artefact (`coverage.xml`).

### Première analyse du code remédié : le gate échoue

| Condition | Valeur | Statut |
|---|---|---|
| Note de sécurité | **E** (2 vulnérabilités) | **Échec** |
| Note de fiabilité | A | OK |
| Couverture | 89,2 % | OK |

Vulnérabilités restantes :

| Sévérité | Règle | Emplacement | Analyse |
|---|---|---|---|
| BLOCKER | python:S8392 | `app.py:98` | Écoute sur `0.0.0.0` : même faux positif que Bandit B104 (exemption EXC-001) |
| HIGH | python:S4502 | `app.py:9` | Protection CSRF absente : **vraie vulnérabilité**, non détectée par Bandit ni Semgrep |

Ce résultat montre l'intérêt d'ajouter un second outil SAST : malgré la remédiation,
SonarQube a trouvé une faille réelle (CSRF, CWE-352) que les autres outils avaient manquée.

### Traitement et nouvelle analyse : le gate passe

Les deux alertes ont été traitées selon le processus d'exemption (chapitre 6) :

- **S8392** → statut **Faux positif** (EXC-001, même analyse que Bandit B104) ;
- **S4502** → statut **Accepté** (EXC-002) : risque réduit par le cookie
  `SameSite=Lax`, remédiation (`Flask-WTF`) planifiée avec une révision à 3 mois.

| Condition | Valeur | Statut |
|---|---|---|
| Note de sécurité | **A** | OK |
| Note de fiabilité | A | OK |
| Couverture | 89,2 % | OK |
| Nouvelles alertes | 0 | OK |

**Quality Gate SonarQube : succès.**
