# 1. Introduction et contexte

## 1.1 Objectif

L'objectif du projet est de concevoir et mettre en œuvre un pipeline CI/CD
**DevSecOps** de bout en bout pour une application web Python Flask volontairement
vulnérable. La sécurité est intégrée à chaque étape du cycle de livraison
(approche *shift-left*) au lieu d'être vérifiée uniquement avant la mise en production.

Le projet couvre les exigences suivantes :

| Exigence | Où elle est traitée |
|---|---|
| Pipeline initial en mode audit (rapports de référence) | [03-phase-as-is.md](03-phase-as-is.md) |
| Quality Gates bloquants sur HIGH/CRITICAL | [04-quality-gates.md](04-quality-gates.md) |
| Correction du code, de Docker et des dépendances | [05-remediation.md](05-remediation.md) |
| Processus d'exemption d'un faux positif | [06-exemptions.md](06-exemptions.md) |
| Rapport avant/après | [07-resultats-conclusion.md](07-resultats-conclusion.md) |

## 1.2 L'application cible

Il s'agit d'une petite application de prise de notes :

| Route | Méthode | Rôle |
|---|---|---|
| `/` | GET | Page d'accueil |
| `/health` | GET | Sonde de santé (utilisée par Docker et le pipeline) |
| `/register` | POST | Création de compte |
| `/login` | POST | Authentification |
| `/notes` | GET, POST | Lecture et ajout de notes (utilisateur connecté) |
| `/search` | GET | Recherche |
| `/ping` | GET | Ping d'un hôte (supprimée lors de la remédiation) |

## 1.3 Failles introduites volontairement

| Faille | Localisation | CWE |
|---|---|---|
| Clé secrète Flask en dur | `app.py` | CWE-798 |
| Token GitHub et clé AWS en dur | `app.py` | CWE-798 |
| Injection SQL dans `/login` | `app.py` | **CWE-89** |
| Hachage des mots de passe en MD5 sans sel | `app.py` | CWE-327 / CWE-916 |
| XSS stockée (`/notes`) et réfléchie (`/search`) | `app.py` | CWE-79 |
| Injection de template côté serveur (SSTI) | `/search` | CWE-1336 |
| Injection de commandes système | `/ping` | CWE-78 |
| Mode debug Flask activé | `app.run(debug=True)` | CWE-489 |
| Dépendances obsolètes (Flask 2.0.1, Werkzeug 2.0.1) | `requirements.txt` | CWE-1104 |
| Image de base obsolète (`python:3.8`), exécution en root | `Dockerfile` | CWE-250 |

## 1.4 Outils utilisés

| Catégorie | Outil | Ce qu'il analyse |
|---|---|---|
| Tests unitaires | **Pytest** | Comportement fonctionnel et tests de sécurité (SQLi, XSS, en-têtes) |
| Secrets | **Gitleaks** | Clés, tokens et mots de passe dans le code |
| SAST | **Bandit** | Code Python (motifs dangereux) |
| SAST / qualité | **SonarQube** (Community, Docker Desktop) | Vulnérabilités, *security hotspots*, bugs, couverture de tests ; remplace Semgrep utilisé en phase As-Is |
| SCA | **Trivy (filesystem)** | CVE des dépendances déclarées (`requirements.txt`) |
| IaC | **Checkov** | Mauvaises configurations du `Dockerfile` et des workflows GitHub Actions |
| SBOM | **Trivy** | Inventaire des composants de l'image (CycloneDX) |
| Conteneurisation | **Docker / Docker Desktop** | Build de l'image, environnements de staging et de production |
| Scan de conteneur | **Trivy (image)** | CVE du système et des paquets de l'image construite |
| DAST | **OWASP ZAP (baseline)** | Application en cours d'exécution (en-têtes, cookies, etc.) |
