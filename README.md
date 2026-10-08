# DevSecOps training app (remediated)

A Flask notes app that started intentionally vulnerable, secured through a CI/CD pipeline
with enforced security quality gates. The full project report (in French) is in
[docs/report/](docs/report/README.md).

Run tests locally (Python 3.12):

    python -m venv venv && source venv/bin/activate
    pip install -r requirements-dev.txt
    python -m pytest tests/ -v

Run with Docker:

    docker build -t devsecops-app .
    docker run -p 5000:5000 -e SECRET_KEY="$(openssl rand -hex 32)" devsecops-app

Pipeline (`.github/workflows/devsecops.yml`): Pytest -> Gitleaks, Bandit, SonarQube,
Trivy fs, Hadolint -> Docker build -> Syft SBOM -> Trivy image -> OWASP ZAP baseline.

SonarQube runs in Docker Desktop on a self-hosted runner. Start it with
`docker compose -f sonarqube/docker-compose.yml up -d` (dashboard: http://localhost:9000).

Scanner exemptions are documented in [exemption-process.md](exemption-process.md).
