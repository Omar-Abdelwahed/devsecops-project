<#
  Deploys the app image to Docker Desktop as a hardened container (levels 5 and 6).

  .\scripts\deploy.ps1 -Environment staging    -Image devsecops-app:<sha> -Port 5001
  .\scripts\deploy.ps1 -Environment production -Image devsecops-app:<sha> -Port 8080

  The secret key comes from the SECRET_KEY environment variable. If the new container
  fails its health check, it is removed and the previous one is restored (rollback).
#>
param(
    [Parameter(Mandatory)][ValidateSet("staging", "production")][string]$Environment,
    [Parameter(Mandatory)][string]$Image,
    [Parameter(Mandatory)][int]$Port
)
# "Continue", not "Stop": Windows PowerShell 5.1 turns docker's stderr into terminating errors
# under "Stop". Every docker call is checked through $LASTEXITCODE instead.
$ErrorActionPreference = "Continue"

if (-not $env:SECRET_KEY) { throw "SECRET_KEY is not set" }

$name     = "devsecops-$Environment"
$previous = "$name-previous"
$network  = "devsecops-$Environment-net"

docker network inspect $network *> $null
if ($LASTEXITCODE -ne 0) { docker network create $network | Out-Null }

# Keep the running version aside so it can be restored.
docker rm -f $previous *> $null
docker inspect $name *> $null
$hadPrevious = ($LASTEXITCODE -eq 0)
if ($hadPrevious) {
    docker stop $name | Out-Null
    docker rename $name $previous
}

# Minimal privileges: read-only filesystem, no Linux capabilities, no privilege escalation,
# resource limits, dashboard port bound to this PC only. /data (SQLite) is the only writable path.
docker run -d --name $name --network $network `
    -p "127.0.0.1:${Port}:5000" `
    --read-only --tmpfs /tmp `
    --cap-drop ALL --security-opt no-new-privileges:true `
    --memory 256m --pids-limit 100 `
    -v "${name}-data:/data" `
    -e SECRET_KEY `
    --restart unless-stopped `
    $Image | Out-Null
$started = ($LASTEXITCODE -eq 0)

function Wait-Healthy {
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $r = Invoke-WebRequest "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 3
            if ($r.StatusCode -eq 200) { return $true }
        } catch { }
        Start-Sleep -Seconds 2
    }
    return $false
}

if ($started -and (Wait-Healthy)) {
    docker rm -f $previous *> $null
    Write-Host "$Environment is up: http://127.0.0.1:$Port ($Image)"
    exit 0
}

# The new version did not start, or started unhealthy: remove it and restore the previous one.
if ($started) {
    Write-Host "Health check failed for $Image. Container logs:"
    docker logs $name
} else {
    Write-Host "docker run failed for $Image."
}
docker rm -f $name *> $null
if ($hadPrevious) {
    docker rename $previous $name
    docker start $name | Out-Null
    if (Wait-Healthy) { Write-Host "Rolled back to the previous $Environment version: it is healthy." }
    else { Write-Host "Rolled back, but the previous $Environment version is not healthy either." }
}
exit 1
