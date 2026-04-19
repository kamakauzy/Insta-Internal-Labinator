<#
.SYNOPSIS
    L.5 — Deploy intentionally vulnerable Docker containers
.DESCRIPTION
    Deploys a collection of intentionally vulnerable containers for practicing:
    - Container escape (privileged, host mounts, CAP_SYS_ADMIN)
    - Docker socket exposure
    - Vulnerable application images (Log4Shell, Spring4Shell, etc.)
    - Registry misconfigurations

.PARAMETER TargetHost
    SSH target (user@ip). Default: root@192.168.56.200

.PARAMETER Local
    Deploy locally instead of via SSH.

.NOTES
    Requires Docker on the target host.
    Version: 1.0.0
#>

param(
    [string]$TargetHost = "root@192.168.56.200",
    [switch]$Local,
    [switch]$Teardown
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  L.5 — Vulnerable Containers                    │" -ForegroundColor Cyan
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

$composeContent = @'
version: '3.8'

services:
  # ── Container Escape Practice ──
  privileged-container:
    image: alpine:latest
    container_name: lab-escape-privileged
    command: ["sleep", "infinity"]
    privileged: true
    pid: host
    volumes:
      - /:/host
    restart: unless-stopped
    networks:
      - vuln-containers

  docker-socket-exposed:
    image: alpine:latest
    container_name: lab-escape-socket
    command: ["sh", "-c", "apk add --no-cache docker-cli && sleep infinity"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    restart: unless-stopped
    networks:
      - vuln-containers

  cap-sys-admin:
    image: alpine:latest
    container_name: lab-escape-capsysadmin
    command: ["sleep", "infinity"]
    cap_add:
      - SYS_ADMIN
      - SYS_PTRACE
    security_opt:
      - apparmor:unconfined
    restart: unless-stopped
    networks:
      - vuln-containers

  # ── Vulnerable Applications ──
  log4shell:
    image: ghcr.io/christophetd/log4shell-vulnerable-app:latest
    container_name: lab-log4shell
    ports:
      - "8090:8080"
    restart: unless-stopped
    networks:
      - vuln-containers

  spring4shell:
    image: vulfocus/spring-core-rce-2022-22965:latest
    container_name: lab-spring4shell
    ports:
      - "8091:8080"
    restart: unless-stopped
    networks:
      - vuln-containers

  # ── Vulnerable Registry ──
  insecure-registry:
    image: registry:2
    container_name: lab-insecure-registry
    ports:
      - "5000:5000"
    environment:
      REGISTRY_HTTP_HEADERS_Access-Control-Allow-Origin: "['*']"
      REGISTRY_HTTP_HEADERS_Access-Control-Allow-Methods: "['HEAD', 'GET', 'OPTIONS', 'DELETE']"
    restart: unless-stopped
    networks:
      - vuln-containers

  # ── SSH Honeypot-style Container ──
  vuln-ssh:
    image: rastasheep/ubuntu-sshd:18.04
    container_name: lab-vuln-ssh
    ports:
      - "2222:22"
    restart: unless-stopped
    networks:
      - vuln-containers

  # ── Redis (no auth) ──
  redis-noauth:
    image: redis:7-alpine
    container_name: lab-redis-noauth
    ports:
      - "6379:6379"
    command: ["redis-server", "--protected-mode", "no"]
    restart: unless-stopped
    networks:
      - vuln-containers

  # ── MongoDB (no auth) ──
  mongo-noauth:
    image: mongo:6
    container_name: lab-mongo-noauth
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_DATABASE: admin
    restart: unless-stopped
    networks:
      - vuln-containers

networks:
  vuln-containers:
    driver: bridge
'@

function Deploy-Compose {
    param([string]$Content, [string]$FileName, [string]$Target, [bool]$IsLocal, [bool]$IsTeardown)

    if ($IsLocal) {
        $path = Join-Path $PSScriptRoot $FileName
        $Content | Out-File -FilePath $path -Encoding UTF8 -Force

        if ($IsTeardown) {
            docker compose -f $path down -v
            Write-Host "    [+] Containers torn down" -ForegroundColor Green
        } else {
            docker compose -f $path up -d
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    [+] Containers started" -ForegroundColor Green
            } else {
                Write-Host "    [-] Docker compose failed" -ForegroundColor Red
            }
        }
    } else {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $Content | Out-File -FilePath $tempFile -Encoding UTF8 -Force
        scp $tempFile "${Target}:/tmp/${FileName}"
        Remove-Item $tempFile -Force

        $action = if ($IsTeardown) { "down -v" } else { "up -d" }
        $result = ssh $Target "cd /tmp && docker compose -f $FileName $action 2>&1"
        $result | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    }
}

if ($Teardown) {
    Write-Host "  [*] Tearing down vulnerable containers..." -ForegroundColor Yellow
    Deploy-Compose -Content $composeContent -FileName "docker-compose-vulncontainers.yml" `
        -Target $TargetHost -IsLocal $Local.IsPresent -IsTeardown $true
    return
}

Write-Host "  [*] Deploying vulnerable containers..." -ForegroundColor Yellow
Deploy-Compose -Content $composeContent -FileName "docker-compose-vulncontainers.yml" `
    -Target $TargetHost -IsLocal $Local.IsPresent -IsTeardown $false

$targetIP = if ($Local) { "localhost" } else { ($TargetHost -split "@")[1] }
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  Vulnerable Containers Deployed                  │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Container Escapes:                              │" -ForegroundColor Green
Write-Host "  │    Privileged:    lab-escape-privileged           │" -ForegroundColor Green
Write-Host "  │    Docker Socket: lab-escape-socket               │" -ForegroundColor Green
Write-Host "  │    CAP_SYS_ADMIN: lab-escape-capsysadmin          │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Vulnerable Apps:                                │" -ForegroundColor Green
Write-Host "  │    Log4Shell:  http://${targetIP}:8090           │" -ForegroundColor Green
Write-Host "  │    Spring4Shell: http://${targetIP}:8091         │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Exposed Services:                               │" -ForegroundColor Green
Write-Host "  │    Registry: http://${targetIP}:5000 (no auth)   │" -ForegroundColor Green
Write-Host "  │    SSH:      ${targetIP}:2222 (root/root)        │" -ForegroundColor Green
Write-Host "  │    Redis:    ${targetIP}:6379 (no auth)          │" -ForegroundColor Green
Write-Host "  │    MongoDB:  ${targetIP}:27017 (no auth)         │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Scan with: trivy image, trivy_scan, nuclei      │" -ForegroundColor Green
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
