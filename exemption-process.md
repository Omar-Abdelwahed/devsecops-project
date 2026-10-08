# Processus d'exemption des faux positifs

Ce document décrit comment une règle d'un scanner de sécurité peut être ignorée
dans le pipeline sans affaiblir les Quality Gates. Une exemption n'est jamais
silencieuse : elle est justifiée, approuvée, tracée dans Git et datée.

## 1. Quand une exemption est-elle acceptable ?

Une exemption est acceptée uniquement si l'une des conditions suivantes est remplie :

| Cas | Exemple | Accepté ? |
|---|---|---|
| **Faux positif** : l'outil signale un motif qui n'est pas exploitable dans notre contexte | `0.0.0.0` dans un conteneur | Oui |
| **Risque accepté** : la vulnérabilité est réelle mais un contrôle compensatoire existe, et aucun correctif n'est disponible | CVE sans version corrigée, composant non exposé | Oui, avec date d'expiration courte |
| La correction est simplement « trop longue » | Requête SQL concaténée | **Non** — il faut corriger |
| Sévérité HIGH/CRITICAL avec correctif disponible | CVE Flask corrigée en 2.3.2 | **Non** — il faut mettre à jour |

## 2. Étapes du processus

1. **Analyse** : le développeur reproduit l'alerte et démontre pourquoi elle n'est pas exploitable.
2. **Choix du mécanisme** (du plus ciblé au plus large) :
   - Bandit : commentaire `# nosec BXXX` sur la ligne, ou `skips` dans `bandit.yaml`
   - SonarQube : commentaire `# NOSONAR` sur la ligne, ou statut « Faux positif » /
     « Accepté » attribué à l'alerte dans l'interface (tracé avec l'auteur et un commentaire)
   - Trivy : fichier `.trivyignore` (un identifiant CVE par ligne, avec `exp:` pour l'expiration)
   - Gitleaks : fichier `.gitleaksignore` (empreinte exacte du secret détecté)
   - OWASP ZAP : règle passée à `IGNORE` dans `rules.tsv`
3. **Documentation** : ajout d'une entrée dans le registre ci-dessous (identifiant `EXC-XXX`),
   et d'un commentaire renvoyant à cet identifiant dans le fichier de configuration.
4. **Revue** : l'exemption passe par une Pull Request relue par une deuxième personne
   (le fichier de configuration et ce document sont modifiés dans le même commit).
5. **Expiration** : chaque exemption a une date de révision. À cette date, elle est
   réévaluée puis supprimée ou renouvelée.

## 3. Registre des exemptions

| ID | Outil | Règle | Fichier concerné | Type | Approuvée le | Révision |
|---|---|---|---|---|---|---|
| EXC-001 | Bandit + SonarQube | B104 (MEDIUM) / python:S8392 (BLOCKER) | `app/app.py` | Faux positif | 2026-10-08 | 2027-04-08 |
| EXC-002 | SonarQube | python:S4502 — protection CSRF absente (HIGH) | `app/app.py` | Risque accepté | 2026-10-08 | 2027-01-08 |

### EXC-001 — Écoute sur toutes les interfaces (Bandit B104, SonarQube S8392)

**Alertes :** la même ligne est signalée par deux outils.

```
MEDIUM   B104         app/app.py:98  Possible binding to all interfaces.               (Bandit)
BLOCKER  python:S8392 app/app.py:98  Avoid binding the application to all network interfaces. (SonarQube)
```

**Analyse :** l'application tourne dans un conteneur Docker. À l'intérieur d'un
conteneur, écouter sur `127.0.0.1` rendrait l'application inaccessible : le
port publié (`-p 5000:5000`) redirige le trafic vers l'interface réseau du
conteneur, pas vers son loopback. L'exposition réelle est contrôlée par Docker
et par le réseau, pas par l'adresse d'écoute. De plus, cette ligne n'est
utilisée qu'en développement (`python app/app.py`) ; en production, l'image
lance `gunicorn --bind 0.0.0.0:5000`.

**Mécanismes retenus :**

- **Bandit :** `skips: [B104]` dans [`bandit.yaml`](bandit.yaml), chargé par le pipeline
  via `bandit -r app -ll -c bandit.yaml`.
- **SonarQube :** l'alerte S8392 est passée au statut **Faux positif** dans l'interface
  SonarQube, avec un commentaire renvoyant à EXC-001. SonarQube conserve l'auteur, la
  date et la justification, et ne recompte plus l'alerte lors des analyses suivantes.
  Contrairement à `bandit.yaml`, ce statut est stocké dans la base SonarQube et non
  dans Git : la sauvegarde du volume PostgreSQL fait donc partie du processus.

**Compromis :** `skips` désactive B104 pour tout le projet, alors que
`# nosec B104` ne vise qu'une ligne. Le fichier central a été choisi pour que
l'exemption soit visible et relue au même endroit que les autres paramètres du
scanner. Si le projet grandit, il faudra revenir à un `# nosec B104` ciblé pour
ne pas masquer une future vraie occurrence.

**Preuve (avant / après) :**

```text
# Sans le fichier de configuration -> le Quality Gate échoue
$ bandit -r app -ll
>> Issue: [B104:hardcoded_bind_all_interfaces] Possible binding to all interfaces.
   Severity: Medium   Confidence: Medium   Location: app/app.py:98
exit code 1

# Avec bandit.yaml -> le Quality Gate passe
$ bandit -r app -ll -c bandit.yaml
No issues identified.
exit code 0
```

### EXC-002 — Protection CSRF absente (SonarQube S4502)

**Alerte :**

```
HIGH  python:S4502  app/app.py:9  Make sure disabling CSRF protection is safe here.
```

**Analyse :** l'alerte est **fondée**. Les routes `POST` (`/register`, `/login`,
`/notes`) n'exigent aucun jeton CSRF : un site malveillant pourrait faire envoyer
une requête par le navigateur d'un utilisateur connecté (CWE-352). Bandit et Semgrep
ne l'avaient pas détectée.

**Pourquoi un risque accepté et non un faux positif :** la vulnérabilité existe, mais
un contrôle compensatoire réduit fortement son impact :

- le cookie de session est configuré avec `SESSION_COOKIE_SAMESITE="Lax"` : le
  navigateur ne l'envoie pas avec une requête `POST` provenant d'un autre site, ce qui
  bloque le CSRF sur `/notes` ;
- `SESSION_COOKIE_HTTPONLY=True` empêche la lecture du cookie par JavaScript.

**Risque résiduel :** le *login CSRF* (forcer la victime à se connecter au compte de
l'attaquant) n'est pas couvert par `SameSite`, car il ne nécessite aucun cookie
existant. Impact jugé faible pour une application de prise de notes.

**Mécanisme retenu :** l'alerte est passée au statut **Accepté** dans SonarQube, avec
un commentaire renvoyant à EXC-002. Un risque accepté reste visible dans SonarQube
(filtre « Accepté »), contrairement à un faux positif.

**Plan de remédiation :** ajouter `Flask-WTF` (`CSRFProtect`) et exiger un jeton CSRF
sur toutes les requêtes `POST`. Date de révision courte (3 mois) : 2027-01-08.

**Preuve (avant / après) :**

| Analyse SonarQube | Note de sécurité | Quality Gate |
|---|---|---|
| Avant traitement (S8392 + S4502 ouvertes) | E | Échec |
| Après EXC-001 (faux positif) et EXC-002 (accepté) | A | Succès |

## 4. Ce qu'une exemption ne doit jamais faire

- Désactiver un scanner entier, ou ajouter `continue-on-error: true` sur un job.
- Baisser le seuil de sévérité global (par exemple passer `HIGH,CRITICAL` à `CRITICAL`).
- Ignorer un secret réel : un secret exposé doit être **révoqué**, puis retiré du code.
