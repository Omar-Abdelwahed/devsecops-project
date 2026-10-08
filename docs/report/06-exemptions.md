# 6. Gestion des faux positifs (exemptions)

Le processus complet et le registre des exemptions sont décrits dans
[`exemption-process.md`](../../exemption-process.md). Ce chapitre résume la démarche.

## 6.1 Pourquoi un processus d'exemption ?

Avec des Quality Gates stricts, un faux positif bloque toute l'équipe. Sans
processus clair, la tentation est de désactiver le scanner ou de remettre
`continue-on-error: true`, ce qui annule tout le travail des chapitres 3 et 4.
Une exemption doit donc être **ciblée, justifiée, relue et limitée dans le temps**.

## 6.2 Cas traité : Bandit B104

Après remédiation, Bandit signale une dernière alerte, de sévérité MEDIUM donc bloquante :

```
MEDIUM B104 app/app.py:98 Possible binding to all interfaces.
```

```python
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

**Pourquoi c'est un faux positif :** dans un conteneur Docker, l'application **doit**
écouter sur `0.0.0.0`. Si elle écoutait sur `127.0.0.1`, le port publié par Docker
(`-p 5000:5000`) ne pourrait pas l'atteindre. L'exposition réelle est contrôlée par
Docker et le réseau. Cette ligne n'est en plus utilisée qu'en développement :
l'image de production lance Gunicorn.

## 6.3 Mise en œuvre

L'exemption est déclarée dans un fichier de configuration dédié,
[`bandit.yaml`](../../bandit.yaml), qui porte son identifiant et sa justification :

```yaml
# EXC-001 | B104 hardcoded_bind_all_interfaces | app/app.py
#   Reason   : false positive. The app runs inside a container, where binding to
#              0.0.0.0 is required for the port mapping to work. ...
#   Approved : 2026-10-08, review by 2027-04-08
skips:
  - B104
```

Le pipeline charge ce fichier explicitement :

```yaml
- name: Bandit (blocking on Medium+)
  run: bandit -r app -ll -c bandit.yaml -f json -o bandit-report.json
```

## 6.4 Preuve avant / après

| Commande | Résultat | Code retour |
|---|---|---|
| `bandit -r app -ll` | `B104` signalé (MEDIUM) | 1 — le gate échoue |
| `bandit -r app -ll -c bandit.yaml` | Aucune alerte | 0 — le gate passe |

## 6.5 Garde-fous

- L'exemption est limitée à **une seule règle** (B104) ; Bandit reste actif pour toutes
  les autres, et le seuil MEDIUM n'a pas été modifié.
- Elle est **versionnée dans Git** : toute modification de `bandit.yaml` est visible
  dans l'historique et passe par une revue.
- Elle a une **date de révision** (2027-04-08).
- **Limite assumée :** `skips` s'applique à tout le projet, alors qu'un commentaire
  `# nosec B104` ne viserait qu'une ligne. Le fichier central a été préféré pour que
  toutes les exemptions soient réunies et relues au même endroit. Le compromis est
  documenté dans `exemption-process.md`.

## 6.6 Exemptions dans SonarQube

La première analyse SonarQube du code remédié a remonté deux vulnérabilités (voir
4.6). Elles illustrent les deux types d'exemption :

| ID | Règle | Statut SonarQube | Raison |
|---|---|---|---|
| EXC-001 | python:S8392 (BLOCKER) — écoute sur `0.0.0.0` | **Faux positif** | Même ligne et même analyse que Bandit B104 |
| EXC-002 | python:S4502 (HIGH) — CSRF absent | **Accepté** | Vraie vulnérabilité, atténuée par `SameSite=Lax` ; correction (`Flask-WTF`) planifiée, révision 2027-01-08 |

**Différence entre les deux statuts :**

- un **faux positif** signifie « l'outil se trompe » : l'alerte n'est pas une vulnérabilité ;
- un **risque accepté** signifie « la vulnérabilité existe, mais on la tolère
  temporairement » : elle doit avoir une justification, un contrôle compensatoire et
  une date de révision courte.

Dans les deux cas, un commentaire renvoyant au registre (`EXC-00X`) est obligatoire.
SonarQube trace l'auteur et la date du changement de statut. Résultat : note de
sécurité E → A, Quality Gate en échec → succès.

> Capture suggérée : l'onglet *Issues* de SonarQube filtré sur « Faux positif » et
> « Accepté », montrant les commentaires EXC-001 et EXC-002.

## 6.7 Mécanismes équivalents pour les autres outils

| Outil | Mécanisme |
|---|---|
| Bandit | `# nosec BXXX` (ligne) ou `skips` dans `bandit.yaml` (projet) |
| SonarQube | `# NOSONAR` (ligne) ou statut « Faux positif » dans l'interface, avec commentaire obligatoire |
| Trivy | `.trivyignore` (identifiant CVE, avec date d'expiration `exp:`) |
| Gitleaks | `.gitleaksignore` (empreinte exacte de la détection) |
| OWASP ZAP | Règle passée en `IGNORE` dans `rules.tsv` |
