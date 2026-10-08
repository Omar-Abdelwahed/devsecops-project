# Rapport de projet DevSecOps — Pipeline CI/CD sécurisé pour une application Flask

**Dépôt :** [Omar-Abdelwahed/devsecops-project](https://github.com/Omar-Abdelwahed/devsecops-project)
**Date :** octobre 2026

## Sommaire

1. [Introduction et contexte](01-introduction.md)
2. [Architecture du pipeline](02-architecture.md)
3. [Phase « As-Is » : audit initial](03-phase-as-is.md)
4. [Phase « To-Be » : Quality Gates](04-quality-gates.md)
5. [Remédiation](05-remediation.md)
6. [Gestion des faux positifs (exemptions)](06-exemptions.md)
7. [Résultats, bilan et conclusion](07-resultats-conclusion.md)

## Résumé

Une application Flask volontairement vulnérable (secrets en dur, injection SQL, XSS,
SSTI, injection de commandes, MD5, mode debug, dépendances obsolètes, image Docker
exécutée en root) a été intégrée dans un pipeline GitHub Actions qui enchaîne neuf
contrôles : tests unitaires, détection de secrets, SAST, SCA, lint du Dockerfile,
SBOM, scan d'image et DAST.

Le projet s'est déroulé en trois temps :

1. **As-Is** : les scanners tournent en mode audit (`continue-on-error`, `|| true`)
   pour établir une base de référence sans bloquer les livraisons.
2. **To-Be** : les Quality Gates sont activés ; le pipeline échoue dès qu'une
   vulnérabilité HIGH/CRITICAL (ou MEDIUM pour Bandit) est détectée.
3. **Remédiation** : correction du code, durcissement de l'image Docker, mise à jour
   des dépendances et documentation d'une exemption, jusqu'à obtenir un pipeline vert.

## Captures d'écran

Les six captures sont à placer dans le dossier [`images/`](images/) avec les noms
indiqués dans [images/README.md](images/README.md).
