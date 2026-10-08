# 5. Remédiation

Ce chapitre présente, pour chaque vulnérabilité, le code **avant** et **après** correction.

## 5.1 Secrets en dur (CWE-798)

**Avant :**

```python
app.secret_key = "super-secret-key-123"
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
```

**Après :**

```python
app.secret_key = os.environ["SECRET_KEY"]  # injected at runtime, never committed
```

- Le token GitHub et la clé AWS sont supprimés : l'application n'en a pas besoin.
- La clé Flask est lue dans une variable d'environnement. `os.environ[...]` (et non
  `.get()` avec une valeur par défaut) fait **planter l'application au démarrage** si
  la variable est absente : impossible de tourner en production avec une clé connue.
- Dans le pipeline, la clé est générée à chaque exécution : `-e SECRET_KEY="$(openssl rand -hex 32)"`.

**Point important :** supprimer un secret du code ne suffit pas, il reste dans
l'historique Git. Un vrai secret exposé doit être **révoqué immédiatement** auprès du
fournisseur (GitHub, AWS). Ici, les valeurs étaient factices.

## 5.2 Injection SQL (CWE-89)

**Avant :**

```python
row = conn.execute(
    f"SELECT * FROM users WHERE username = '{u}' AND password = '{hash_pw(p)}'"
).fetchone()
```

**Après :**

```python
row = conn.execute("SELECT password FROM users WHERE username = ?", (u,)).fetchone()  # parameterized
conn.close()
if row and check_password_hash(row[0], p):
```

La **requête paramétrée** (`?`) transmet la valeur séparément de la requête SQL :
le pilote SQLite la traite toujours comme une donnée, jamais comme du code SQL.
L'entrée `admin' --` est alors simplement un nom d'utilisateur qui n'existe pas.

Un test unitaire vérifie que l'attaque échoue :

```python
def test_sqli_blocked():
    c = app.test_client()
    c.post("/register", data={"username": "admin", "password": "realpassword"})
    r = c.post("/login", data={"username": "admin' --", "password": "anything"})
    assert r.status_code == 401
```

## 5.3 Hachage MD5 des mots de passe (CWE-327)

**Avant :** `hashlib.md5(pw.encode()).hexdigest()` — rapide à casser, sans sel.

**Après :** `generate_password_hash()` / `check_password_hash()` de Werkzeug
(algorithme lent et salé : scrypt par défaut). La comparaison se fait en Python et
plus dans la requête SQL. La colonne `username` est aussi devenue `UNIQUE`.

## 5.4 XSS et SSTI (CWE-79, CWE-1336)

**Avant :**

```python
return render_template_string(f"<h2>Results for {q}</h2>")     # SSTI + XSS réfléchie
return "".join(f"<li>{r[0]}</li>" for r in rows)                # XSS stockée
```

**Après :**

```python
return f"<h2>Results for {escape(request.args.get('q', ''))}</h2>"
return "".join(f"<li>{escape(r[0])}</li>" for r in rows) or "no notes"
```

`render_template_string` est supprimé (plus d'évaluation de template à partir d'une
entrée utilisateur) et toutes les données affichées passent par `markupsafe.escape`.
Le test `test_search_xss_escaped` vérifie que `<script>` est rendu `&lt;script&gt;`.

## 5.5 Injection de commandes (CWE-78)

**Avant :** `os.popen('ping -c 1 ' + host)` — l'entrée `127.0.0.1; cat /etc/passwd`
exécute une seconde commande.

**Après :** la route `/ping` est **supprimée**. Elle n'avait aucune utilité métier ;
supprimer une fonctionnalité inutile est la remédiation la plus sûre (réduction de la
surface d'attaque).

## 5.6 Mode debug (CWE-489)

**Avant :** `app.run(host="0.0.0.0", port=5000, debug=True)`

**Après :** `debug=True` est supprimé et, en production, l'application n'est plus
servie par le serveur de développement Flask mais par **Gunicorn**
(`gunicorn --bind 0.0.0.0:5000 --workers 2 app.app:app`).

## 5.7 En-têtes de sécurité HTTP (alertes ZAP)

Ajout d'un hook exécuté après chaque requête :

```python
@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp
```

Les cookies de session sont aussi durcis : `SESSION_COOKIE_HTTPONLY=True` et
`SESSION_COOKIE_SAMESITE="Lax"`.

## 5.8 Dépendances (CWE-1104)

| Paquet | Avant | Après | CVE corrigées |
|---|---|---|---|
| flask | 2.0.1 | 3.1.3 | CVE-2023-30861 |
| werkzeug | 2.0.1 | 3.1.9 | CVE-2023-25577, CVE-2024-34069 |
| jinja2 | 3.0.1 | 3.1.6 | — |
| markupsafe | 2.0.1 | 3.0.4 | — |
| itsdangerous | 2.0.1 | 2.2.0 | — |
| click | 8.0.1 | 8.5.0 | — |
| blinker | — | 1.9.0 | (dépendance de Flask 3, désormais épinglée) |
| gunicorn | — | 26.2.0 | (nouveau : serveur WSGI de production) |
| pytest | 7.0.0 (dans l'image) | 9.1.1 (dans `requirements-dev.txt`) | — |

Deux changements de structure :

- **Toutes les versions sont épinglées** (`==`), y compris les dépendances
  transitives : un build donne toujours le même résultat, et Trivy analyse exactement
  ce qui est installé.
- **Séparation production / développement** : `pytest` est déplacé dans
  `requirements-dev.txt`. L'image de production ne contient plus les outils de test.

## 5.9 Durcissement de l'image Docker (CWE-250)

**Avant :**

```dockerfile
FROM python:3.8
WORKDIR /code
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app/app.py"]
```

**Après :**

```dockerfile
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /code
RUN useradd --system --uid 10001 --no-create-home appuser && chown appuser /code
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip uninstall -y pip
COPY app/ ./app/
USER 10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://localhost:5000/health')"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app.app:app"]
```

| Mesure | Bénéfice |
|---|---|
| `python:3.12-slim` au lieu de `python:3.8` | Python maintenu, image minimale : beaucoup moins de paquets système donc moins de CVE |
| Utilisateur `appuser` (UID 10001), `USER 10001` | Une compromission de l'application ne donne pas les droits root dans le conteneur |
| `COPY app/` au lieu de `COPY . .` + fichier `.dockerignore` | Ni `.git`, ni tests, ni fichiers `.env` dans l'image |
| `pip install --no-cache-dir` | Image plus légère |
| `pip uninstall -y pip` | pip n'est pas utile à l'exécution, et ses bibliothèques embarquées (urllib3, msgpack, setuptools) étaient signalées en CVE HIGH par Trivy image |
| `HEALTHCHECK` | Docker détecte une application bloquée |
| Gunicorn | Serveur WSGI de production au lieu du serveur de développement |

**Problèmes détectés par les nouveaux outils pendant la remédiation :**

- **Hadolint** a signalé `DL3025` (la commande `HEALTHCHECK` doit utiliser la notation
  JSON) et `DL3066` (utilisateur non numérique, non résolvable par l'hôte). Corrigés
  avec la notation JSON et `USER 10001`.
- **Trivy image** a signalé 4 CVE HIGH (urllib3, msgpack, setuptools) qui ne venaient
  pas de nos dépendances mais des bibliothèques **embarquées dans pip** lui-même.
  Corrigé en désinstallant pip à la fin du build.

## 5.10 Tests unitaires

Fichiers [`tests/conftest.py`](../../tests/conftest.py) et [`tests/test_app.py`](../../tests/test_app.py).
Le job `unit-tests` s'exécute en premier dans le pipeline.

| Test | Ce qu'il vérifie |
|---|---|
| `test_health` | La sonde `/health` répond `{"status": "ok"}` |
| `test_register_login_notes` | Parcours complet : inscription, connexion, ajout et lecture d'une note |
| `test_login_rejects_bad_password` | Un mauvais mot de passe est refusé (401) |
| `test_sqli_blocked` | L'injection `admin' --` ne contourne pas l'authentification |
| `test_search_xss_escaped` | Une charge XSS dans `/search` est échappée |
| `test_security_headers` | Les trois en-têtes de sécurité sont présents |

`conftest.py` définit une `SECRET_KEY` de test et une base SQLite temporaire avant
l'import de l'application, pour que les tests n'utilisent aucun vrai secret ni la
vraie base.

Résultat : **6 tests réussis**.

## 5.11 SBOM (Syft)

Après le build, Syft inventorie tous les composants de l'image (paquets Debian et
Python) et produit deux SBOM standards, publiés en artefact :

- `sbom.cyclonedx.json` (format CycloneDX, OWASP)
- `sbom.spdx.json` (format SPDX, Linux Foundation)

Le SBOM permet de répondre immédiatement à la question « sommes-nous concernés ? »
lorsqu'une nouvelle CVE est publiée, sans avoir à reconstruire l'image.
