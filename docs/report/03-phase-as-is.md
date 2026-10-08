# 3. Phase « As-Is » : audit initial

## 3.1 Principe

Dans un premier temps, les scanners sont ajoutés au pipeline **sans bloquer la
livraison**. L'objectif est de mesurer la dette de sécurité existante (la *baseline*)
avant d'imposer des règles. Activer des Quality Gates directement sur un projet
existant bloquerait toute l'équipe du jour au lendemain.

Le mode audit est obtenu de deux façons (commit `d777a92`) :

```yaml
jobs:
  sast-sca-scan:
    runs-on: ubuntu-latest
    continue-on-error: true          # le job ne fait jamais échouer le pipeline
    steps:
      - name: Run Bandit
        run: bandit -r app.py -f json -o bandit-report.json -ll || true   # code retour ignoré
```

Résultat : le pipeline est **vert** alors que l'application est très vulnérable.
Les rapports JSON/HTML sont téléchargés comme artefacts pour analyse.

![Capture 1 — Graphe du pipeline As-Is](images/01-pipeline-as-is.png)

> **Capture 1** — Pipeline As-Is : tous les jobs s'exécutent en mode audit, le pipeline
> se termine en succès malgré les vulnérabilités.

## 3.2 Secrets — Gitleaks

Gitleaks a analysé tout l'historique Git (`detect` avec `fetch-depth: 0`) et a
détecté le token GitHub écrit en dur dans `app/app.py` :

```python
app.secret_key = "super-secret-key-123"                    # clé Flask en dur
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"  # token (factice)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"                 # clé AWS (factice)
```

![Capture 2 — Gitleaks détecte le token GitHub](images/02-gitleaks-token.png)

> **Capture 2** — Gitleaks signale la règle `github-pat` dans `app/app.py`.

**Remarque :** la clé AWS utilisée est la clé d'exemple officielle de la documentation
AWS (`AKIAIOSFODNN7EXAMPLE`). Gitleaks l'ignore volontairement grâce à sa liste
d'autorisation interne, ce qui montre qu'un scanner de secrets ne détecte pas tout :
Bandit (B105) et la revue de code restent nécessaires.

## 3.3 SAST — Bandit

Résultat de `bandit -r app -l` sur la version vulnérable (commit `8f7768b`) :

| Sévérité | Règle | Ligne | Description | CWE |
|---|---|---|---|---|
| HIGH | B324 | 27 | Hachage MD5 pour les mots de passe | CWE-327 |
| HIGH | B605 | 92 | Lancement d'un shell avec entrée utilisateur (`os.popen`) | CWE-78 |
| HIGH | B201 | 98 | Flask lancé avec `debug=True` (débogueur Werkzeug exposé) | CWE-94 |
| **MEDIUM** | **B608** | **57** | **Requête SQL construite par concaténation de chaînes** | **CWE-89** |
| MEDIUM | B104 | 98 | Écoute sur toutes les interfaces (`0.0.0.0`) | CWE-605 |
| LOW | B105 | 9 | Mot de passe en dur (`secret_key`) | CWE-259 |
| LOW | B105 | 10 | Mot de passe en dur (`GITHUB_TOKEN`) | CWE-259 |

**Total : 7 alertes (3 HIGH, 2 MEDIUM, 2 LOW).**

La faille la plus critique est l'injection SQL dans `/login` :

```python
row = conn.execute(
    f"SELECT * FROM users WHERE username = '{u}' AND password = '{hash_pw(p)}'"
).fetchone()
```

Avec le nom d'utilisateur `admin' --`, la fin de la requête est commentée et la
vérification du mot de passe disparaît : on se connecte en tant qu'`admin` sans
connaître son mot de passe.

![Capture 3 — Bandit B608, injection SQL (CWE-89)](images/03-bandit-cwe89.png)

> **Capture 3** — Bandit signale B608 (CWE-89) à la ligne 57 de `app/app.py`.

## 3.4 SAST — Semgrep puis SonarQube

### Semgrep (pipeline As-Is d'origine)

Dans le pipeline As-Is, Semgrep (`--config auto`) complétait Bandit avec des règles
spécifiques à Flask : injection SQL, `render_template_string` avec entrée utilisateur
(SSTI/XSS), injection de commandes, mode debug.

> [à compléter : nombre d'alertes Semgrep relevé dans `semgrep-report.json` de l'exécution As-Is]

### SonarQube (baseline rétroactive)

Semgrep a ensuite été remplacé par SonarQube (voir chapitre 2). Pour disposer d'une
baseline comparable, la version vulnérable (commit `8f7768b`) a été analysée dans un
projet SonarQube séparé, `devsecops-project-asis`, avec le même Quality Gate.

**Résultat : Quality Gate en échec — note de sécurité E, 6 vulnérabilités, couverture 0 %.**

| Sévérité | Règle | Emplacement | Description |
|---|---|---|---|
| BLOCKER | python:S8392 | `app.py:98` | Application liée à toutes les interfaces réseau (`0.0.0.0`) |
| HIGH | python:S4502 | `app.py:8` | Protection CSRF absente |
| HIGH | python:S4790 | `app.py:27` | Algorithme de hachage faible (MD5) |
| HIGH | docker:S6470 | `Dockerfile:6` | Copie récursive (`COPY . .`) pouvant inclure des données sensibles |
| LOW | python:S4507 | `app.py:98` | Mode debug activé |
| LOW | docker:S6471 | `Dockerfile:2` | L'image `python` s'exécute en root par défaut |

S'y ajoutent 4 alertes de maintenabilité (S6965 : méthodes HTTP non précisées sur
une route).

**Ce que SonarQube Community n'a pas détecté :** l'injection SQL (`/login`),
l'injection de commandes (`/ping`), la XSS et la SSTI (`/search`). La détection de ces
failles repose sur l'**analyse de teinte** (*taint analysis*, suivi d'une entrée
utilisateur jusqu'à une fonction dangereuse), réservée aux éditions payantes de
SonarQube. À l'inverse, SonarQube a trouvé l'absence de protection CSRF et les
problèmes du Dockerfile, que Bandit ne voit pas.

| Faille | Bandit | SonarQube Community |
|---|---|---|
| Injection SQL (CWE-89) | Oui (B608) | Non |
| Injection de commandes (CWE-78) | Oui (B605) | Non |
| MD5 (CWE-327) | Oui (B324) | Oui (S4790) |
| Mode debug | Oui (B201) | Oui (S4507) |
| Écoute sur `0.0.0.0` | Oui (B104) | Oui (S8392) |
| CSRF absent (CWE-352) | Non | **Oui (S4502)** |
| Dockerfile (root, `COPY . .`) | Non | **Oui (S6471, S6470)** |

Aucun outil ne couvre tout : c'est la combinaison Bandit + SonarQube (+ tests de
sécurité Pytest) qui couvre l'ensemble des failles.

## 3.5 SCA — Trivy filesystem

Résultat de `trivy fs --severity HIGH,CRITICAL --ignore-unfixed` sur `requirements.txt` :

| Paquet | Version | CVE | Sévérité | Corrigé en | Description |
|---|---|---|---|---|---|
| flask | 2.0.1 | CVE-2023-30861 | HIGH | 2.2.5 / 2.3.2 | Fuite possible du cookie de session permanent (en-tête `Vary: Cookie` manquant) |
| werkzeug | 2.0.1 | CVE-2023-25577 | HIGH | 2.2.3 | Consommation excessive de ressources lors du parsing multipart (déni de service) |
| werkzeug | 2.0.1 | CVE-2024-34069 | HIGH | 3.0.3 | Exécution de code sur le poste du développeur via le débogueur |

**Total : 3 CVE HIGH, 0 CRITICAL.**

Les quatre autres paquets (`click`, `itsdangerous`, `jinja2`, `markupsafe`) et
`pytest` n'apparaissent pas : ils n'ont aucune CVE HIGH/CRITICAL disposant d'un correctif.

### Table de correspondance CVE / CVSS

Le score **CVSS** (*Common Vulnerability Scoring System*, de 0,0 à 10,0) mesure la
gravité d'une CVE. Le **vecteur** décrit les conditions de l'attaque :

| Élément du vecteur | Signification |
|---|---|
| `AV:N` | Attaque possible à distance, par le réseau |
| `AC:L` / `AC:H` | Complexité d'attaque faible / élevée |
| `PR:N` | Aucun compte ni privilège nécessaire |
| `UI:N` / `UI:R` | Aucune action de la victime / action de la victime requise |
| `C` / `I` / `A` | Impact sur la confidentialité / l'intégrité / la disponibilité (`H` = élevé, `N` = aucun) |

La colonne **Atteignable ?** répond à une question que l'outil ne pose pas : la
fonctionnalité vulnérable est-elle réellement utilisée par **notre** application ?
Trivy compare seulement des numéros de version.

| Paquet | Version | CVE | CWE | CVSS 3.1 | Vecteur | Sévérité | Corrigé en | Atteignable ? | Action |
|---|---|---|---|---|---|---|---|---|---|
| flask | 2.0.1 | CVE-2023-30861 | CWE-539 | 7,5 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | HIGH | 2.2.5 / 2.3.2 | **Non** | Mise à jour vers 3.1.3 |
| werkzeug | 2.0.1 | CVE-2023-25577 | CWE-770 | 7,5 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | HIGH | 2.2.3 | **Oui** | Mise à jour vers 3.1.9 (prioritaire) |
| werkzeug | 2.0.1 | CVE-2024-34069 | CWE-352 | 7,5 | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` | HIGH | 3.0.3 | **Oui en As-Is**, non après remédiation | Mise à jour vers 3.1.9 + suppression de `debug=True` |

Source des scores : GitHub Security Advisories (GHSA) et NVD, d'après le rapport
`trivy-fs.json`. Pour CVE-2023-30861, la GHSA donne aussi un score CVSS 4.0 de 8,7.

**Analyse d'atteignabilité :**

- **CVE-2023-30861 (Flask) — non atteignable.** La fuite du cookie de session exige
  simultanément un proxy de cache entre l'utilisateur et l'application, et
  `session.permanent = True`. L'application ne définit jamais de session permanente
  et n'est pas déployée derrière un proxy de cache.
- **CVE-2023-25577 (Werkzeug) — atteignable.** Le parseur de formulaires multipart
  n'impose aucune limite au nombre de parties. Les routes `/register` et `/login`
  lisent `request.form` **sans authentification** : n'importe quel visiteur peut
  envoyer un formulaire contenant des milliers de parties et saturer le processeur et
  la mémoire, rendant l'application indisponible (déni de service). C'est la CVE la
  plus critique **pour cette application**.
- **CVE-2024-34069 (Werkzeug) — atteignable en As-Is uniquement.** La faille touche le
  débogueur Werkzeug, actif seulement en mode debug. La version As-Is lançait
  `app.run(debug=True)` : un attaquant capable d'amener un développeur sur un domaine
  qu'il contrôle pouvait exécuter du code sur son poste. Après remédiation, le mode
  debug est supprimé et la production utilise Gunicorn : la faille n'est plus atteignable.

**Pourquoi corriger aussi une CVE non atteignable ?** La politique du pipeline bloque
toute CVE HIGH/CRITICAL **corrigeable**, sans tenir compte de l'atteignabilité. La mise
à jour est peu coûteuse, et l'atteignabilité peut changer : il suffirait d'ajouter
`session.permanent = True` dans une future version pour rendre CVE-2023-30861
exploitable. Une exemption (`.trivyignore`) ne serait justifiée que pour une CVE à la
fois non atteignable **et** sans correctif disponible.

## 3.6 Scan de conteneur — Trivy image

L'image d'origine était construite sur `python:3.8` (image complète, version de
Python en fin de vie depuis octobre 2024), s'exécutait en **root**, copiait tout le
dépôt (`COPY . .`) et lançait le serveur de développement Flask :

```dockerfile
FROM python:3.8
WORKDIR /code
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app/app.py"]
```

> [à compléter : nombre de CVE HIGH / CRITICAL relevé dans `trivy-image-report.json` de l'exécution As-Is]

## 3.7 DAST — OWASP ZAP baseline

ZAP a exploré l'application en cours d'exécution. Les principales alertes
concernaient l'absence d'en-têtes de sécurité HTTP :

| ID ZAP | Alerte | Risque |
|---|---|---|
| 10020 | En-tête anti-clickjacking absent (`X-Frame-Options`) | Moyen |
| 10021 | En-tête `X-Content-Type-Options` absent | Faible |
| 10038 | En-tête `Content-Security-Policy` absent | Moyen |
| 10036 | Le serveur divulgue sa version (`Server: Werkzeug/...`) | Faible |

> [à vérifier : compléter ou ajuster ce tableau à partir de la capture 4]

![Capture 4 — Tableau de bord HTML d'OWASP ZAP](images/04-zap-dashboard.png)

> **Capture 4** — Rapport HTML ZAP de l'exécution As-Is.

## 3.8 Synthèse de la baseline

| Catégorie | Outil | Résultat As-Is |
|---|---|---|
| Secrets | Gitleaks | Token GitHub détecté |
| SAST | Bandit | 7 alertes (3 HIGH, 2 MEDIUM, 2 LOW) |
| SAST | Semgrep | [à compléter] |
| SAST | SonarQube (baseline rétroactive) | Gate en échec : note E, 6 vulnérabilités (1 BLOCKER, 3 HIGH, 2 LOW) |
| SCA | Trivy fs | 3 CVE HIGH |
| Conteneur | Trivy image | [à compléter] |
| DAST | ZAP | En-têtes de sécurité absents (10020, 10021, 10038) |
| **Statut du pipeline** | | **Vert (mode audit), alors que l'application est vulnérable** |
