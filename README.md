# DevSecOps training app (remediated)

A Flask notes app that started intentionally vulnerable, secured by a multi-level DevSecOps
pipeline. The full project report (in French) is in [docs/report/](docs/report/README.md).

## Architecture

| Level | Where | What runs |
|---|---|---|
| Development (shift-left) | Developer PC | pre-commit: Gitleaks, Bandit, Checkov. Full local scan: `.\scripts\local-scan.ps1` |
| 1 Build & Test | GitHub-hosted runner | Pytest + coverage, Docker build |
| 2 Security Scans | GitHub-hosted + self-hosted | Gitleaks, Bandit, SonarQube, Trivy fs (SCA), Checkov (IaC), Trivy image + SBOM |
| 3 Report Generation | GitHub-hosted runner | One JSON / Markdown / HTML report from all scanners |
| 4 Security Gate | GitHub-hosted runner | `security-policy.json` applied: BLOCK or PASS (fails closed) |
| 5 Staging + DAST | Self-hosted (Docker Desktop) | Hardened staging container on 127.0.0.1:5001, OWASP ZAP baseline |
| 6 Manual Approval & Deploy | Self-hosted (Docker Desktop) | Waits for approval, deploys production on 127.0.0.1:8080, rollback on failure |
| Alerts | GitHub-hosted runner | Discord message on block, failure or deployment |

Each level is its own reusable workflow (`.github/workflows/level*.yml`), chained by
`.github/workflows/devsecops.yml`. Levels 5 and 6 only run for pushes to `main`.

## Run locally

Tests (Python 3.12):

    pip install -r requirements-dev.txt
    python -m pytest tests/ -v

All scanners + the Security Gate, with Docker only:

    .\scripts\local-scan.ps1

SonarQube (dashboard http://localhost:9000):

    docker compose -f sonarqube/docker-compose.yml up -d

## One-time GitHub setup

- Self-hosted runner on the team PC, label `docker-desktop`
- Environments: `staging`, and `production` with a required reviewer
- Secrets: `SONAR_TOKEN`, `PROD_SECRET_KEY` (production environment), `DISCORD_WEBHOOK_URL`

Scanner exemptions are documented in [exemption-process.md](exemption-process.md).
