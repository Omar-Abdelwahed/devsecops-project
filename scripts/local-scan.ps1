<#
  Development level (shift-left): runs the same scanners, report and Security Gate as the
  CI pipeline, on this PC, through Docker Desktop. Nothing to install except Docker.

  .\scripts\local-scan.ps1                 # everything, SonarQube included if SONAR_TOKEN is set
  .\scripts\local-scan.ps1 -SkipImage      # code-only scans (faster, no docker build)

  Reports are written to .\reports-local\ (git-ignored).
#>
param([switch]$SkipImage)
$ErrorActionPreference = "Continue"   # docker writes progress to stderr; exit codes are checked instead

$repo = (Get-Location).Path
$out = Join-Path $repo "reports-local"
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory $out | Out-Null
docker volume create trivy-cache | Out-Null   # keeps Trivy's vulnerability database between runs

function Step($name) { Write-Host "`n=== $name" -ForegroundColor Cyan }

Step "Secrets (Gitleaks)"
docker run --rm -v "${repo}:/repo" zricethezav/gitleaks:latest dir /repo --redact --exit-code 0 `
    --report-format json --report-path /repo/reports-local/gitleaks-report.json

Step "SAST (Bandit)"
docker run --rm -v "${repo}:/src" -w /src python:3.12-slim sh -c `
    "pip install -q --root-user-action=ignore bandit 2>/dev/null; bandit -r app -c bandit.yaml -f json -o reports-local/bandit-report.json --exit-zero -q"

Step "SCA (Trivy filesystem)"
docker run --rm -v "${repo}:/work" -w /work -v trivy-cache:/root/.cache/trivy aquasec/trivy:latest fs `
    --scanners vuln --skip-dirs reports-local --format json --output reports-local/trivy-fs.json .

Step "IaC (Checkov)"
docker run --rm -v "${repo}:/src" -w /src bridgecrew/checkov:latest --config-file .checkov.yaml `
    --output json --output-file-path reports-local/checkov --soft-fail | Out-Null
Move-Item "$out\checkov\results_json.json" "$out\checkov-report.json"

$skip = @()
if ($SkipImage) {
    $skip += "trivy-image"
} else {
    Step "Docker build + container scan (Trivy image)"
    docker build -q -t devsecops-app:local . | Out-Null
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${repo}:/work" -w /work `
        -v trivy-cache:/root/.cache/trivy aquasec/trivy:latest image --scanners vuln `
        --format json --output reports-local/trivy-image.json devsecops-app:local
}

if ($env:SONAR_TOKEN) {
    Step "SAST + quality (SonarQube)"
    docker run --rm -v "${repo}:/src" -w /src -e PYTHONDONTWRITEBYTECODE=1 python:3.12-slim sh -c `
        "pip install -q --root-user-action=ignore -r requirements-dev.txt 2>/dev/null; python -m pytest tests/ -q -p no:cacheprovider --junitxml=pytest-report.xml --cov=app --cov-report=xml" | Out-Null
    docker run --rm --network sonarnet -e SONAR_HOST_URL=http://sonarqube:9000 -e SONAR_TOKEN `
        -v "${repo}:/usr/src" sonarsource/sonar-scanner-cli:latest *> "$out\sonarqube-scan.log"
    $status = if ($LASTEXITCODE -eq 0) { "OK" } else { "ERROR" }
    @{ quality_gate = $status } | ConvertTo-Json | Out-File -Encoding ascii "$out\sonarqube-result.json"
} else {
    Write-Host "`nSONAR_TOKEN not set: SonarQube skipped." -ForegroundColor Yellow
    $skip += "sonarqube"
}

Step "Report + Security Gate"
$skipArgs = if ($skip.Count) { "--skip " + ($skip -join " ") } else { "" }
docker run --rm -v "${repo}:/src" -w /src python:3.12-slim sh -c `
    "python scripts/security_report.py reports-local reports-local/report > /dev/null && python scripts/security_gate.py reports-local/report/summary.json security-policy.json --out reports-local/gate-result.json $skipArgs"
$gate = $LASTEXITCODE
Write-Host "HTML report: $out\report\security-report.html"
exit $gate
